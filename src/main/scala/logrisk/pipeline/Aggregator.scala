package logrisk.pipeline

import logrisk.domain.{LogEntry, RiskEvent}
import java.security.MessageDigest
import java.time.Instant
import scala.collection.mutable

object Aggregator {

  def hashIp(ip: String, secret: String): String = {
    val md = MessageDigest.getInstance("SHA-256")
    val hashedBytes = md.digest((ip + secret).getBytes("UTF-8"))
    hashedBytes.map("%02x".format(_)).mkString.substring(0, 16)
  }

  def aggregate(entries: List[LogEntry], ipHashSecret: String): (Map[String, Int], Map[Int, Int], Map[String, Int], List[RiskEvent]) = {
    val topEndpoints = mutable.Map.empty[String, Int].withDefaultValue(0)
    val statusBreakdown = mutable.Map.empty[Int, Int].withDefaultValue(0)
    val suspiciousAgents = mutable.Map.empty[String, Int].withDefaultValue(0)
    
    val ip404Count = mutable.Map.empty[String, Int].withDefaultValue(0)
    val ipRequestCount = mutable.Map.empty[String, Int].withDefaultValue(0)
    
    // Group sensitive paths by IP Hash to avoid spam
    val ipSensitivePaths = mutable.Map.empty[String, mutable.Set[String]]
    
    val riskEvents = mutable.ListBuffer.empty[RiskEvent]
    
    val sensitivePaths = Set("/.env", "/wp-admin", "/wp-login.php", "/.git", "/phpmyadmin", "/admin", "/server-status", "/actuator", "/debug")
    val suspiciousUserAgentsSet = Set("curl", "python-requests", "go-http-client", "masscan", "nmap", "sqlmap", "nikto", "zgrab")

    if (entries.isEmpty) return (Map.empty, Map.empty, Map.empty, List.empty)
    
    val start = entries.map(_.timestamp).minOption.getOrElse(Instant.now())
    val end = entries.map(_.timestamp).maxOption.getOrElse(Instant.now())

    entries.foreach { entry =>
      val ipHash = hashIp(entry.remoteAddr, ipHashSecret)
      
      topEndpoints(entry.path) += 1
      statusBreakdown(entry.status) += 1
      ipRequestCount(ipHash) += 1
      
      if (entry.status == 404) {
        ip404Count(ipHash) += 1
      }
      
      val agentLower = entry.userAgent.toLowerCase
      val isSuspiciousAgent = suspiciousUserAgentsSet.exists(agentLower.contains) || entry.userAgent.trim.isEmpty
      if (isSuspiciousAgent) {
        suspiciousAgents(entry.userAgent) += 1
      }
      
      // Record sensitive path probes
      if (sensitivePaths.exists(entry.path.contains)) {
        val pathsSet = ipSensitivePaths.getOrElseUpdate(ipHash, mutable.Set.empty[String])
        if (pathsSet.size < 5) { // Keep only up to 5 examples to save space
          pathsSet += entry.path
        }
      }
    }
    
    // Aggregate risks
    
    // 1. Sensitive Path Probes (Deduplicated)
    ipSensitivePaths.foreach { case (ipHash, paths) =>
      val examples = paths.take(3).mkString(", ") + (if (paths.size > 3) "..." else "")
      riskEvents += RiskEvent(
        score = 80,
        severity = "high",
        reason = "Multiple sensitive path probes",
        evidence = s"Paths accessed: $examples",
        firstSeen = start,
        lastSeen = end,
        requestCount = paths.size, // this is just unique sample size now, but it's enough indicator
        relatedIpHash = Some(ipHash)
      )
    }

    // 2. High 404 Count
    ip404Count.foreach { case (ipHash, count) =>
      if (count > 20) {
        riskEvents += RiskEvent(
          score = 60,
          severity = "medium",
          reason = "High 404 count",
          evidence = s"$count 404s recorded",
          firstSeen = start,
          lastSeen = end,
          requestCount = count,
          relatedIpHash = Some(ipHash)
        )
      }
    }
    
    // 3. Burst Traffic
    ipRequestCount.foreach { case (ipHash, count) =>
      if (count > 1000) {
        riskEvents += RiskEvent(
          score = 90,
          severity = "critical",
          reason = "Burst traffic / DoS attempt",
          evidence = s"$count requests recorded in window",
          firstSeen = start,
          lastSeen = end,
          requestCount = count,
          relatedIpHash = Some(ipHash)
        )
      }
    }

    (
      topEndpoints.toSeq.sortBy(-_._2).take(10).toMap,
      statusBreakdown.toMap,
      suspiciousAgents.toSeq.sortBy(-_._2).take(10).toMap,
      riskEvents.toList
    )
  }
}
