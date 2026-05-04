package logrisk.web

import cats.effect.IO
import io.circe.generic.auto.*
import io.circe.syntax.*
import logrisk.AppConfig
import logrisk.domain.*
import logrisk.jobs.Scheduler
import logrisk.parser.NginxParser
import logrisk.pipeline.Aggregator
import logrisk.storage.ReportRepository
import org.http4s.*
import org.http4s.circe.*
import org.http4s.dsl.io.*
import org.http4s.server.staticcontent.*
import doobie.implicits.*
import cats.syntax.all.*
import java.time.Instant
import java.util.UUID

object Routes {
  implicit val reportEncoder: EntityEncoder[IO, Report] = jsonEncoderOf[IO, Report]
  implicit val reportListEncoder: EntityEncoder[IO, List[Report]] = jsonEncoderOf[IO, List[Report]]

  def publicRoutes(config: AppConfig): HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "health" =>
      Ok("""{"status":"ok","service":"scala-logrisk-pipeline"}""")
  }

  def protectedApiRoutes(config: AppConfig): HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "api" / "reports" =>
      ReportRepository.getAll().transact(ReportRepository.transactor).flatMap(Ok(_))

    case GET -> Root / "api" / "reports" / id =>
      ReportRepository.getById(id).transact(ReportRepository.transactor).flatMap {
        case Some(report) => Ok(report)
        case None => NotFound()
      }

    case POST -> Root / "api" / "analyze" =>
      Scheduler.runAnalysis(config, "manual").flatMap(_ => Ok("""{"status":"analysis_started"}"""))
      
    case req @ POST -> Root / "api" / "analyze" / "sample" =>
      req.as[String].flatMap { body =>
        if (body.length > config.maxSampleBytes) {
          BadRequest("Sample too large")
        } else {
          val lines = body.split("\n").toList
          val entries = lines.flatMap(NginxParser.parseLine)
          
          val (topEndpoints, statusBreakdown, suspiciousAgents, riskEvents) = Aggregator.aggregate(entries, config.ipHashSecret)
          
          val start = entries.map(_.timestamp).minOption.getOrElse(Instant.now())
          val end = entries.map(_.timestamp).maxOption.getOrElse(Instant.now())
          val uniqueClients = entries.map(e => Aggregator.hashIp(e.remoteAddr, config.ipHashSecret)).toSet.size
          
          val report = Report(
            id = UUID.randomUUID().toString,
            sourceName = "sample",
            analyzedAt = Instant.now(),
            timeRangeStart = start,
            timeRangeEnd = end,
            totalRequests = entries.size,
            uniqueClients = uniqueClients,
            topEndpointsJson = topEndpoints.asJson.noSpaces,
            statusBreakdownJson = statusBreakdown.asJson.noSpaces,
            suspiciousAgentsJson = suspiciousAgents.asJson.noSpaces,
            riskEventsJson = riskEvents.asJson.noSpaces,
            notes = "Sample analysis"
          )
          
          ReportRepository.insert(report).transact(ReportRepository.transactor) *>
          ReportRepository.cleanup(config.maxReports).transact(ReportRepository.transactor) *>
          Ok(report)
        }
      }
  }

  def staticRoutes(): HttpRoutes[IO] = resourceServiceBuilder[IO]("/public").toRoutes

  def dashboardRoutes(): HttpRoutes[IO] = HttpRoutes.of[IO] {
    case request @ GET -> Root =>
      StaticFile.fromResource("/public/index.html", Some(request)).getOrElseF(NotFound())
    case request @ GET -> Root / "report" / id =>
      StaticFile.fromResource("/public/report.html", Some(request)).getOrElseF(NotFound())
  }
}
