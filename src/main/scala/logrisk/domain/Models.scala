package logrisk.domain

import java.time.Instant
import io.circe.generic.auto.*
import io.circe.syntax.*
import io.circe.Codec

case class LogEntry(
  timestamp: Instant,
  remoteAddr: String,
  method: String,
  path: String,
  status: Int,
  bodyBytes: Long,
  referer: String,
  userAgent: String
)

case class RiskEvent(
  score: Int, // 0 to 100
  severity: String, // low, medium, high, critical
  reason: String,
  evidence: String,
  firstSeen: Instant,
  lastSeen: Instant,
  requestCount: Int,
  relatedIpHash: Option[String] = None,
  relatedEndpoint: Option[String] = None,
  relatedUserAgent: Option[String] = None
) derives Codec.AsObject

case class Report(
  id: String,
  sourceName: String,
  analyzedAt: Instant,
  timeRangeStart: Instant,
  timeRangeEnd: Instant,
  totalRequests: Int,
  uniqueClients: Int,
  topEndpointsJson: String,
  statusBreakdownJson: String,
  suspiciousAgentsJson: String,
  riskEventsJson: String,
  notes: String
)
