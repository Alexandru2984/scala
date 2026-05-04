package logrisk.parser

import logrisk.domain.LogEntry
import java.time.format.DateTimeFormatter
import java.time.{ZonedDateTime, ZoneId}
import java.util.Locale
import scala.util.Try

object NginxParser {
  // Example: 127.0.0.1 - - [04/May/2026:12:34:56 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
  private val logRegex = """^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+) HTTP/\d\.\d" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$""".r
  
  // Nginx time format: 04/May/2026:12:34:56 +0000
  private val formatter = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH)

  def parseLine(line: String): Option[LogEntry] = {
    line match {
      case logRegex(ip, timeStr, method, pathWithQuery, statusStr, bytesStr, referer, userAgent) =>
        Try {
          val timestamp = ZonedDateTime.parse(timeStr, formatter).toInstant
          val status = statusStr.toInt
          val bytes = if (bytesStr == "-") 0L else bytesStr.toLong
          
          // Strip query string for safety
          val path = pathWithQuery.takeWhile(_ != '?')

          LogEntry(
            timestamp = timestamp,
            remoteAddr = ip,
            method = method,
            path = path,
            status = status,
            bodyBytes = bytes,
            referer = referer,
            userAgent = userAgent
          )
        }.toOption
      case _ => None
    }
  }
}
