package logrisk.web

import cats.data.Kleisli
import cats.effect.IO
import logrisk.AppConfig
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.headers.Authorization
import org.mindrot.jbcrypt.BCrypt

object Auth {
  def authMiddleware(config: AppConfig): Kleisli[IO, Request[IO], Either[String, Unit]] = Kleisli { req =>
    req.headers.get[Authorization] match {
      case Some(Authorization(BasicCredentials(user, pass))) =>
        if (user == config.authUsername && BCrypt.checkpw(pass, config.authPasswordHash)) {
          IO.pure(Right(()))
        } else {
          IO.pure(Left("Unauthorized"))
        }
      case _ => IO.pure(Left("Unauthorized"))
    }
  }

  val authUser: Kleisli[IO, Request[IO], Either[String, Unit]] = Kleisli(req => IO.pure(Right(()))) // dummy, we'll use middleware manually

  def withAuth(config: AppConfig)(routes: HttpRoutes[IO]): HttpRoutes[IO] = Kleisli { req =>
    routes(req).flatMap { response =>
      // If the route matched, check auth
      cats.data.OptionT.liftF(authMiddleware(config).run(req)).flatMap {
        case Right(_) => cats.data.OptionT.pure[IO](response)
        case Left(_) => cats.data.OptionT.pure[IO](
          Response[IO](status = Status.Unauthorized).withHeaders(headers.`WWW-Authenticate`(Challenge("Basic", "LogRisk")))
        )
      }
    }
  }
}
