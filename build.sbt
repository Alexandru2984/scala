val Http4sVersion = "0.23.25"
val CirceVersion = "0.14.6"
val DoobieVersion = "1.0.0-RC5"

lazy val root = (project in file("."))
  .settings(
    organization := "com.micutu",
    name := "scala-logrisk-pipeline",
    version := "0.1.0",
    scalaVersion := "3.3.3",
    libraryDependencies ++= Seq(
      "org.http4s"      %% "http4s-ember-server" % Http4sVersion,
      "org.http4s"      %% "http4s-circe"        % Http4sVersion,
      "org.http4s"      %% "http4s-dsl"          % Http4sVersion,
      "io.circe"        %% "circe-generic"       % CirceVersion,
      "io.circe"        %% "circe-parser"        % CirceVersion,
      "org.tpolecat"    %% "doobie-core"         % DoobieVersion,
      "org.tpolecat"    %% "doobie-hikari"       % DoobieVersion,
      "org.xerial"       % "sqlite-jdbc"         % "3.45.1.0",
      "com.github.pureconfig" %% "pureconfig-core" % "0.17.6",
      "ch.qos.logback"   % "logback-classic"     % "1.4.14",
      "io.github.cdimascio" % "java-dotenv"      % "5.2.2",
      "co.fs2"          %% "fs2-io"              % "3.9.4",
      "org.mindrot"      % "jbcrypt"             % "0.4"
    )
  )

assembly / assemblyMergeStrategy := {
  case PathList("META-INF", "versions", "9", "module-info.class") => MergeStrategy.discard
  case PathList("META-INF", xs @ _*) => MergeStrategy.discard
  case "module-info.class" => MergeStrategy.discard
  case x => MergeStrategy.first
}
