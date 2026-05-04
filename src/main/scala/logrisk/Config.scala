package logrisk

case class AppConfig(
  appEnv: String,
  appHost: String,
  appPort: Int,
  appBaseUrl: String,
  authUsername: String,
  authPasswordHash: String,
  logInputPaths: String,
  analysisIntervalMinutes: Int,
  maxSampleBytes: Int,
  storeRawLogs: Boolean,
  anonymizeIps: Boolean,
  ipHashSecret: String,
  maxReports: Int
)

object Config {
  def load(): AppConfig = {
    // Load .env properties to System properties if missing (useful for local run)
    io.github.cdimascio.dotenv.Dotenv.configure().ignoreIfMissing().load().entries().forEach(entry =>
      if (System.getProperty(entry.getKey) == null) System.setProperty(entry.getKey, entry.getValue)
    )

    def getEnv(key: String, default: String = ""): String =
      sys.env.getOrElse(key, System.getProperty(key, default))

    AppConfig(
      appEnv = getEnv("APP_ENV", "production"),
      appHost = getEnv("APP_HOST", "127.0.0.1"),
      appPort = getEnv("APP_PORT", "8080").toInt,
      appBaseUrl = getEnv("APP_BASE_URL", "http://127.0.0.1:8080"),
      authUsername = getEnv("AUTH_USERNAME", "admin"),
      authPasswordHash = getEnv("AUTH_PASSWORD_HASH", ""),
      logInputPaths = getEnv("LOG_INPUT_PATHS", "/var/log/nginx/access.log"),
      analysisIntervalMinutes = getEnv("ANALYSIS_INTERVAL_MINUTES", "15").toInt,
      maxSampleBytes = getEnv("MAX_SAMPLE_BYTES", "262144").toInt,
      storeRawLogs = getEnv("STORE_RAW_LOGS", "false").toBoolean,
      anonymizeIps = getEnv("ANONYMIZE_IPS", "true").toBoolean,
      ipHashSecret = getEnv("IP_HASH_SECRET", "secret"),
      maxReports = getEnv("MAX_REPORTS", "100").toInt
    )
  }
}
