# Scala LogRisk Pipeline

A compact log intelligence pipeline and web application that consumes Nginx access logs, aggregates traffic patterns, and calculates risk scores for suspicious behavior. Built with Scala 3, http4s, and Cats Effect.

## Features

- **Dashboard:** Modern dark UI showing key log statistics.
- **Log Input Modes:** Read from configured filesystem paths or analyze pasted samples.
- **Log Parsing:** Parses standard Nginx combined log format.
- **Aggregation Pipeline:** Computes top endpoints, status code breakdown, and suspicious user agents.
- **Risk Scoring:** Detects high 404 counts, burst traffic, and sensitive path probing.
- **Reports:** Compact report storage using SQLite.
- **Background Job:** Runs analysis automatically every N minutes.
- **Authentication:** Protected dashboard via HTTP Basic Auth.
- **Privacy:** Client IPs are hashed/anonymized by default using a salt. Raw logs are not stored.

## Stack

- **Backend:** Scala 3, http4s, Cats Effect, Circe, Doobie (SQLite).
- **Frontend:** Vanilla HTML/CSS/JS with Chart.js support.

## How to Build

Requirements: Java 21, sbt.

```bash
sbt assembly
```
The output jar will be in `target/scala-3.3.3/scala-logrisk-pipeline-assembly-0.1.0.jar`.

## How to Run

You can run the app with the generated jar:
```bash
java -jar target/scala-3.3.3/scala-logrisk-pipeline-assembly-0.1.0.jar
```

Ensure the `.env` file is present in the working directory before starting the application.

## Environment Variables

See the `.env` file for the full list of configuration options. Important variables:
- `APP_PORT`: The local port to bind to (default: 8080).
- `AUTH_USERNAME`: Dashboard username.
- `AUTH_PASSWORD_HASH`: BCrypt hash of the dashboard password.
- `LOG_INPUT_PATHS`: Comma-separated list of Nginx log paths to analyze (e.g., `/var/log/nginx/access.log`).
- `ANONYMIZE_IPS`: Set to `true` to hash IPs before aggregation and storage.
- `IP_HASH_SECRET`: The salt used for hashing IPs.

## API Endpoints

- `GET /health` - Public health check.
- `GET /` - Protected dashboard.
- `GET /api/reports` - List recent reports.
- `GET /api/reports/{id}` - Get a specific report.
- `POST /api/analyze` - Trigger background log analysis.
- `POST /api/analyze/sample` - Analyze a pasted sample (max size enforced).

## Security and Privacy

This application is designed to be a safe, focused intelligence layer. 
- It does not store raw log lines, only aggregated metrics and specific risk event evidence.
- Client IPs are one-way hashed by default.
- Path traversal and arbitrary file access are prevented; the background job only reads files explicitly configured in `LOG_INPUT_PATHS`.
- Report database is kept compact by automatically cleaning up old entries.
