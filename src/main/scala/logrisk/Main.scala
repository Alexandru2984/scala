package logrisk

import cats.effect.{IO, IOApp}
import com.comcast.ip4s.*
import logrisk.jobs.Scheduler
import logrisk.storage.ReportRepository
import logrisk.web.{Auth, Routes}
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.Router
import org.http4s.implicits.*
import cats.implicits.*

object Main extends IOApp.Simple {

  def run: IO[Unit] = {
    val config = Config.load()
    
    val publicRoutes = Routes.publicRoutes(config)
    val protectedApi = Auth.withAuth(config)(Routes.protectedApiRoutes(config))
    val dashboard = Auth.withAuth(config)(Routes.dashboardRoutes())
    val static = Routes.staticRoutes() // let static be public or protected, better public so css loads, or protected

    // We protect the static assets too if we want, but usually it's fine.
    // Dashboard handles index.html and report.html
    val httpApp = Router(
      "/" -> (publicRoutes <+> dashboard <+> static),
      "/" -> protectedApi
    ).orNotFound

    for {
      _ <- IO.println(s"Starting Scala LogRisk Pipeline in ${config.appEnv}")
      _ <- ReportRepository.init(config.maxReports)
      
      server = EmberServerBuilder
        .default[IO]
        .withHost(Ipv4Address.fromString(config.appHost).getOrElse(ipv4"127.0.0.1"))
        .withPort(Port.fromInt(config.appPort).getOrElse(port"8080"))
        .withHttpApp(httpApp)
        .build

      backgroundJob = Scheduler.startBackgroundJob(config)

      _ <- (server.useForever, backgroundJob).parTupled
    } yield ()
  }
}
