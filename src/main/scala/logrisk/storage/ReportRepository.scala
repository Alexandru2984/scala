package logrisk.storage

import logrisk.domain.Report
import doobie.*
import doobie.implicits.*
import cats.effect.*
import cats.syntax.all.*
import java.time.Instant
import java.util.UUID

object ReportRepository {

  val transactor = Transactor.fromDriverManager[IO](
    driver = "org.sqlite.JDBC",
    url = "jdbc:sqlite:data/logrisk.sqlite",
    logHandler = None
  )

  val initSchema: ConnectionIO[Int] =
    sql"""
      CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        source_name TEXT NOT NULL,
        analyzed_at TEXT NOT NULL,
        time_range_start TEXT NOT NULL,
        time_range_end TEXT NOT NULL,
        total_requests INTEGER NOT NULL,
        unique_clients INTEGER NOT NULL,
        top_endpoints_json TEXT NOT NULL,
        status_breakdown_json TEXT NOT NULL,
        suspicious_agents_json TEXT NOT NULL,
        risk_events_json TEXT NOT NULL,
        notes TEXT NOT NULL
      )
    """.update.run

  def insert(report: Report): ConnectionIO[Int] =
    sql"""
      INSERT INTO reports (
        id, source_name, analyzed_at, time_range_start, time_range_end,
        total_requests, unique_clients, top_endpoints_json, status_breakdown_json,
        suspicious_agents_json, risk_events_json, notes
      ) VALUES (
        ${report.id}, ${report.sourceName}, ${report.analyzedAt.toString},
        ${report.timeRangeStart.toString}, ${report.timeRangeEnd.toString},
        ${report.totalRequests}, ${report.uniqueClients}, ${report.topEndpointsJson},
        ${report.statusBreakdownJson}, ${report.suspiciousAgentsJson},
        ${report.riskEventsJson}, ${report.notes}
      )
    """.update.run

  def getAll(): ConnectionIO[List[Report]] =
    sql"""
      SELECT id, source_name, analyzed_at, time_range_start, time_range_end,
             total_requests, unique_clients, top_endpoints_json, status_breakdown_json,
             suspicious_agents_json, risk_events_json, notes
      FROM reports
      ORDER BY analyzed_at DESC
      LIMIT 100
    """.query[(String, String, String, String, String, Int, Int, String, String, String, String, String)]
       .map { case (id, src, at, ts, te, req, cli, endp, stat, agnt, risk, notes) =>
         Report(id, src, Instant.parse(at), Instant.parse(ts), Instant.parse(te),
                req, cli, endp, stat, agnt, risk, notes)
       }
       .to[List]

  def getById(id: String): ConnectionIO[Option[Report]] =
    sql"""
      SELECT id, source_name, analyzed_at, time_range_start, time_range_end,
             total_requests, unique_clients, top_endpoints_json, status_breakdown_json,
             suspicious_agents_json, risk_events_json, notes
      FROM reports
      WHERE id = $id
    """.query[(String, String, String, String, String, Int, Int, String, String, String, String, String)]
       .map { case (i, src, at, ts, te, req, cli, endp, stat, agnt, risk, notes) =>
         Report(i, src, Instant.parse(at), Instant.parse(ts), Instant.parse(te),
                req, cli, endp, stat, agnt, risk, notes)
       }
       .option

  def cleanup(maxReports: Int): ConnectionIO[Int] =
    sql"""
      DELETE FROM reports
      WHERE id NOT IN (
        SELECT id FROM reports ORDER BY analyzed_at DESC LIMIT $maxReports
      )
    """.update.run

  def init(maxReports: Int): IO[Unit] = {
    (initSchema *> cleanup(maxReports)).transact(transactor).void
  }
}
