package logrisk.jobs

import cats.effect.*
import cats.syntax.all.*
import logrisk.{Config, AppConfig}
import logrisk.domain.{LogEntry, Report, RiskEvent}
import logrisk.parser.NginxParser
import logrisk.pipeline.Aggregator
import logrisk.storage.ReportRepository
import fs2.io.file.{Files, Path}
import fs2.text
import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*
import io.circe.syntax.*
import doobie.implicits.*
import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}

object Scheduler {

  def processLogFile(pathStr: String, ipHashSecret: String): IO[List[LogEntry]] = {
    val path = Path(pathStr)
    Files[IO].exists(path).flatMap { exists =>
      if (exists) {
        Files[IO].readUtf8Lines(path)
          .map(NginxParser.parseLine)
          .unNone
          .compile
          .toList
      } else {
        IO.pure(List.empty[LogEntry])
      }
    }
  }

  def sendWebhookAlert(webhookUrl: String, riskEvents: List[RiskEvent]): IO[Unit] = IO.blocking {
    if (webhookUrl.nonEmpty && riskEvents.exists(r => r.severity == "critical" || r.severity == "high")) {
      val criticals = riskEvents.count(_.severity == "critical")
      val highs = riskEvents.count(_.severity == "high")
      
      val text = s"🚨 **LogRisk Alert** 🚨\\nDetected **$criticals Critical** and **$highs High** risk events in the latest log analysis.\\nPlease check the dashboard for details."
      val json = s"""{"content": "$text"}"""
      
      val client = HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(5)).build()
      val request = HttpRequest.newBuilder()
        .uri(URI.create(webhookUrl))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(json))
        .build()
      
      client.send(request, HttpResponse.BodyHandlers.ofString())
    }
  }.attempt.void

  def runAnalysis(config: AppConfig, sourceName: String = "scheduled"): IO[Unit] = {
    val paths = config.logInputPaths.split(",").map(_.trim).toList
    
    for {
      _ <- IO.println(s"Starting analysis for paths: $paths")
      entriesNested <- paths.traverse(p => processLogFile(p, config.ipHashSecret))
      entries = entriesNested.flatten
      
      _ <- IO.println(s"Parsed ${entries.size} valid log entries.")
      
      _ <- if (entries.nonEmpty) {
        val (topEndpoints, statusBreakdown, suspiciousAgents, riskEvents) = Aggregator.aggregate(entries, config.ipHashSecret)
        
        val start = entries.map(_.timestamp).minOption.getOrElse(Instant.now())
        val end = entries.map(_.timestamp).maxOption.getOrElse(Instant.now())
        val uniqueClients = entries.map(e => Aggregator.hashIp(e.remoteAddr, config.ipHashSecret)).toSet.size
        
        val report = Report(
          id = UUID.randomUUID().toString,
          sourceName = sourceName,
          analyzedAt = Instant.now(),
          timeRangeStart = start,
          timeRangeEnd = end,
          totalRequests = entries.size,
          uniqueClients = uniqueClients,
          topEndpointsJson = topEndpoints.asJson.noSpaces,
          statusBreakdownJson = statusBreakdown.asJson.noSpaces,
          suspiciousAgentsJson = suspiciousAgents.asJson.noSpaces,
          riskEventsJson = riskEvents.asJson.noSpaces,
          notes = s"Analyzed ${paths.size} files."
        )
        
        ReportRepository.insert(report).transact(ReportRepository.transactor) *>
        ReportRepository.cleanup(config.maxReports).transact(ReportRepository.transactor) *>
        sendWebhookAlert(config.alertWebhookUrl, riskEvents) *>
        IO.println(s"Saved report ${report.id}")
      } else {
        IO.println("No entries to analyze.")
      }
    } yield ()
  }

  def startBackgroundJob(config: AppConfig): IO[Unit] = {
    val interval = config.analysisIntervalMinutes.minutes
    val loop = runAnalysis(config).attempt.flatMap {
      case Left(err) => IO.println(s"Error in scheduled analysis: ${err.getMessage}")
      case Right(_) => IO.unit
    } >> IO.sleep(interval)
    
    loop.foreverM
  }
}
