![Logo](logo.png "Logo")

# SilicaProxy — Artifact Firewall Proxy

SilicaProxy is a **security proxy for artifact repositories** that intercepts every package download and blocks vulnerable, deprecated, or newly published packages before they reach your builds.

It sits between your artifact repository and the public registries (npm, PyPI, Maven Central) and makes a security decision on each package — with a very minimum overhead your CI/CD pipelines and resolutions.

---

## Why SilicaProxy?

| Threat                                  | How SilicaProxy helps |
|-----------------------------------------|---|
| Known CVEs (Log4Shell, ShaiHulud, etc.) | Blocks packages matching local vulnerability databases (OSV, GHSA, GitLab Advisory, OpenSSF) |
| Typosquatting / supply-chain attacks    | Quarantines packages published less than N days ago |
| Deprecated / yanked packages            | Blocks packages flagged as deprecated (npm) or yanked (PyPI) |
| Custom internal rules                   | Company-level allow/block list synchronized from a Git repository (GitOps) |
| Custom deep scanning                    | Integrates any external validation service (sync or async) — SBOM scanners, licence checkers, proprietary scanners |

---

## Architecture

```
Artifact Repository
       │  HTTP or HTTPS (SSL MITM)
       ▼
┌─────────────────────┐
│   LoomProxyServer   │  port 8080 — TCP entry point (HTTP + CONNECT)
│   SslMitmService    │  decrypts HTTPS transparently (CA generated at startup)
└────────┬────────────┘
         │ plain HTTP
         ▼
┌─────────────────────┐
│   ProxyController   │  Spring Boot / Tomcat (port 8089, internal)
│   UrlParserService  │  extracts package name, version, ecosystem
│   SecurityService   │  orchestrates the decision pipeline
└────────┬────────────┘
         │
    ┌────┴──────────────────────────────┐
    │         Decision pipeline         │
    │                                   │
    │  1. company_policies   (priority 1)│  ← GitOps YAML rules
    │  2. public_vulnerabilities (prio 2)│  ← OSV / GHSA / GitLab / OpenSSF
    │  3. api_cache          (priority 3)│  ← cached live API results
    │  (single SQL query, UNION ALL)     │
    └────────────────┬──────────────────┘
                     │ if unknown package
                     ▼
         ┌───────────────────────┐
         │ Registry metadata     │  publication date, deprecated/yanked flag
         │ Quarantine check      │  age < threshold → BLOCK
         │ Deprecation check     │  deprecated/yanked → BLOCK (cached forever)
         │ External validation   │  configurable sync/async services (SBOM, licence, …)
         │ Live API fallback     │  OSV → deps.dev
         └───────────────────────┘
                     │
              ALLOW → stream package to client
              BLOCK → HTTP 403 (RFC 7807 JSON)
```

### Package structure

The codebase is organized around the detection phases a request goes through:

```
com.silicaproxy
├── controller/           REST endpoints (proxy, GitOps, policies, monitoring, search)
├── service/
│   ├── interception/     TCP entry point, SSL MITM, URL/ecosystem parsing
│   ├── policy/           Company policy evaluation, GitOps sync
│   ├── vulnerability/    CVE ingestion, OSV incremental sync, scheduler
│   ├── decision/         SecurityService orchestrator, api_cache cleanup, external validation
│   ├── audit/            Async audit log
│   ├── monitoring/       Health checks, data inventory
│   └── search/           Package search
├── dao/
│   ├── policy/           SQL — company_policies, decision cache, metadata cache, external validation
│   ├── vulnerability/    SQL — public_vulnerabilities
│   ├── sync/             SQL — sync_status, sync_run_history, shedlock, health
│   ├── audit/            SQL — proxy_audit_logs, api_call_log
│   └── client/           HTTP — OSV, deps.dev, registry, Git, proxy stream, external validation
├── config/               Spring configuration (async, HTTP client, SSRF, scheduler)
├── model/
│   ├── dto/              Data transfer objects
│   └── entity/           JPA entities
└── properties/           SilicaProxyProperties (typed config)
```

**Key design choices:**
- **Virtual threads (Project Loom / Java 25)** — thousands of concurrent downloads with near-zero overhead per connection.
- **Single SQL query** — one `UNION ALL` covers all three local sources; the priority ordering ensures company policies always win.
- **Streaming (16 KB buffer)** — binaries are never loaded into JVM memory, keeping the footprint stable regardless of artifact size.
- **Async audit log** — audit writes never block downloads; overflow is handled with a discard policy.

---

## Data Sources

SilicaProxy evaluates security decisions in order of priority, pulling from multiple data sources:

### What "fail-open" / "fail-closed" means

Several of the checks below depend on a remote call that can fail (a registry being
unreachable, an external validation service timing out, the OSV/deps.dev live APIs returning
an error). Each of these checks has a configurable policy for that failure case:

- **`fail-open: true`** (the default almost everywhere) — if the check can't get an answer,
  **allow** the package rather than block a build over an infrastructure hiccup.
- **`fail-open: false`** (i.e. fail-closed) — if the check can't get an answer, **block** the
  package instead, favoring security over availability.

This choice is configured independently for quarantine (`silicaproxy.quarantine.fail-open`,
[§3](#3-public-registry-metadata--on-demand-cached-permanently)), each external validation
service (`...services.<name>.fail-open`, [§4](#4-external-validation-services--on-demand-sync-or-async)),
and each live API fallback source (`silicaproxy.api-fallback.<osv|deps-dev>.fail-open`,
[§5](#5-live-security-api-fallback--on-demand-configurable-cache-priority-3)) — a hardened
environment can flip any of them to fail-closed without affecting the others.

### 1. Company policies — GitOps sync every 10 minutes (Priority 1)

Internal allow/block rules are read from a Git repository containing one YAML file per ecosystem (`npm.yaml`, `pypi.yaml`, `maven.yaml`). The scheduler pulls changes every 10 minutes and synchronises the `company_policies` table. These rules have the **highest priority** in the decision pipeline and always override external vulnerability data.

---

### 2. Public vulnerabilities — nightly batch sync + hourly incremental (Priority 2)

These are downloaded once a day and stored locally in PostgreSQL, so every proxy decision is resolved from a local SQL query with no external dependency at request time.

| Source | What it covers | Format |
|---|---|---|
| **Google OSV** | CVEs for npm, PyPI, Maven | ZIP archives downloaded per ecosystem |
| **GitHub Advisory Database (GHSA)** | Curated security advisories across all ecosystems | Git clone (`github/advisory-database`) |
| **GitLab Advisory Database** | Additional advisories, especially for Ruby/Go/Java | Git clone |
| **OpenSSF Malicious Packages** | Known malware, typosquatting campaigns, sabotage incidents | Git clone |

All six sources (3 OSV ZIPs + 3 Git repositories) are synchronized **in parallel** on virtual threads. A failure in one source (e.g. a Git repository temporarily unreachable) does not block or delay the others. Progress is tracked per-job and visible at `/api/vulnerabilities/sync/status`.

Within a single OSV ZIP, one malformed advisory (unexpected JSON shape) does not abort the whole ~500k-entry run either: it's logged, counted in `sync_run_history.items_failed`, and skipped — the rest of the archive is still ingested, matching the per-advisory resilience of the hourly incremental sync below.

SemVer version ranges from the advisories are flattened into a concrete list of affected versions at ingestion time, enabling a fast JSONB containment check (`@>`) at query time.

#### 2.1 Incremental OSV updates — hourly sync (between nightly batches)

Between nightly batch syncs, SilicaProxy fetches the `modified_id.csv` index files published by Google on the same GCS bucket. These files list every advisory modified in the last N hours, sorted newest-first. The service reads them from the top and stops as soon as it reaches an entry older than the previous `last_end_time` watermark (stored in `sync_status`), so only the delta is downloaded.

| Ecosystem | GCS index file |
|---|---|
| npm | `https://storage.googleapis.com/osv-vulnerabilities/npm/modified_id.csv` |
| PyPI | `https://storage.googleapis.com/osv-vulnerabilities/PyPI/modified_id.csv` |
| Maven | `https://storage.googleapis.com/osv-vulnerabilities/Maven/modified_id.csv` |

For each advisory ID in the delta, the service fetches the corresponding JSON file and upserts it into `public_vulnerabilities`. A failure on a single advisory is logged and skipped — the others are still processed. Three new `sync_status` job IDs track these runs: `osv-npm-incremental`, `osv-pypi-incremental`, `osv-maven-incremental`.

The incremental sync runs **every hour** under ShedLock (`osv-incremental-sync`). On first run (no watermark), it fetches the last `initial-lookback-hours` of changes (default: 25 h) to bridge the gap until the next nightly batch.

### 3. Public registry metadata — on-demand, cached permanently

When a package version is not in any local database, SilicaProxy queries the registry to retrieve:
- **Publication date** — used for the quarantine check (anti-typosquatting)
- **Deprecation / yanked status** — used for the deprecation check (npm and PyPI only)

| Ecosystem | Default registry | Publication date | Deprecation / yanked | YAML / Env var |
|---|---|---|---|---|
| **npm** | `registry.npmjs.org` | ✓ | ✓ (`deprecated` field) | `silicaproxy.registries.npm-url` / `SILICAPROXY_REGISTRIES_NPM_URL` |
| **PyPI** | `pypi.org` | ✓ | ✓ (`yanked` field) | `silicaproxy.registries.pypi-url` / `SILICAPROXY_REGISTRIES_PYPI_URL` |
| **Maven** | `repo1.maven.org` | ✓ (`Last-Modified` header) | — not supported | `silicaproxy.registries.maven-url` / `SILICAPROXY_REGISTRIES_MAVEN_URL` |

The publication date is **stored permanently** in the `package_metadata` table — it never changes, so no subsequent network call is needed for a version already seen. A deprecation verdict is also cached permanently. Only the quarantine verdict is never cached, so it is naturally re-evaluated at each request until the package ages out.

### 4. External Validation Services — on-demand, sync or async

SilicaProxy can call any number of external HTTP services to validate a package before reaching the live API fallback. This is designed for deep scanners that are too slow to block a build synchronously, or for proprietary tools with custom scoring.

#### Sync mode

The proxy makes a POST call to the service and waits up to 1 second for a response. If the service replies in time, the verdict is applied immediately. On timeout or network error, the configurable `fail-open` / `fail-closed` policy applies.

```
POST {url}
Body: { "packageName": "lodash", "version": "4.17.21", "ecosystem": "npm" }

Response: { "verdict": "BLOCKED", "reason": "Malicious dependency detected." }
```

#### Async mode

The proxy fires a POST and returns immediately (applying `fail-open` / `fail-closed`). The service processes the package in the background and calls back the proxy when it has a verdict.

```
POST {url}
Body: { "packageName": "lodash", "version": "4.17.21", "ecosystem": "npm",
        "callbackUrl": "https://proxy.yourcompany.com/external-validation/callback/{token}" }

→ Callback (later): POST /external-validation/callback/{token}
  Header: Authorization: Bearer {api-key}   # only required if api-key is configured for this service
  Body: { "verdict": "ALLOWED", "reason": "Clean." }
```

The callback token is a UUID generated per request. The endpoint returns `404` if the token is unknown or has already been resolved.

If `api-key` is configured for the service (see [Configuration Reference](#full-variable-table)), the callback must present it back as `Authorization: Bearer {api-key}`, or the endpoint returns `401`. This is optional: a service with no `api-key` configured accepts callbacks with no `Authorization` header at all, exactly as before. The unguessable per-request UUID token is itself some protection, but it's not authentication — anyone who learns a pending token (logs, a leaked URL, a network observer) can otherwise forge a verdict for that request without it.

#### Persistence

| Verdict | Destination | Expiry |
|---|---|---|
| BLOCKED (blocking=true) | `external_validation_verdicts` | **Permanent** — no TTL, manual removal only |
| ALLOWED | `external_validation_cache` | Configurable TTL (`cache-ttl-minutes`) |
| PENDING (async, waiting) | `external_validation_cache` | Configurable TTL (`pending-ttl-minutes`), then → TIMEOUT |
| BLOCKED (blocking=false) | `external_validation_verdicts` | **Permanent** — stored for observability, but never enforced as long as `blocking=false` |

A BLOCKED verdict written to `external_validation_verdicts` is **permanent**: it is never cleaned up automatically and is applied on every subsequent request for that package, regardless of any other check.

#### Multi-service execution order

When multiple services are configured:

0. **Short-circuit**: if *any* service with `blocking: true` already has a permanent verdict for this exact package/version (from a previous sync call or async callback), the proxy returns `BLOCK` immediately and skips every network call — to its own service and to every other configured service. This is what makes the permanent block in step 4 actually permanent in practice: once one blocking scanner has spoken, the others are never asked again for that package/version.
1. Otherwise, all **SYNC** services run in parallel — the proxy waits for every sync response.
2. If any sync service produces an effective BLOCK → the package is blocked. ASYNC services are **not triggered**, unless `trigger-async-on-sync-block: true` (in which case they run fire-and-forget to populate the DB for future requests).
3. If all sync services ALLOW → all **ASYNC** services are triggered in parallel (fire-and-forget).
4. Final verdict: **the most restrictive wins** — one BLOCK from any service is enough.

#### `blocking` flag

Each service can be configured with `blocking: false` to make it **informational only**: the verdict is still stored in the DB and appears in audit logs, but never blocks a package. Useful for trialling a new scanner in shadow mode before enforcing it.

#### Configuration example

```yaml
silicaproxy:
  external-validation:
    callback-base-url: "https://proxy.yourcompany.com"   # required for async mode
    trigger-async-on-sync-block: false                   # trigger async even when sync blocks
    services:
      snyk:
        enabled: true
        url: "https://scanner.yourcompany.com/v1/check"
        api-key: "${EXTERNAL_SCANNER_API_KEY}"
        mode: sync
        timeout-seconds: 1
        fail-open: true
        blocking: true
        cache-ttl-minutes: 1440

      deep-scanner:
        enabled: true
        url: "https://deep-scanner.yourcompany.com/analyze"
        api-key: "${DEEP_SCANNER_API_KEY}"
        mode: async
        fail-open: true
        blocking: true
        cache-ttl-minutes: 10080
        pending-ttl-minutes: 60

      package-name-guardian:
        enabled: true
        url: "https://package-name-guardian.yourcompany.com/api/v1/check"
        api-key: "${PACKAGE_NAME_GUARDIAN_API_KEY}"
        mode: sync
        timeout-seconds: 1
        fail-open: true
        blocking: true
        cache-ttl-minutes: 10080
```

**Package-Name-Guardian example:** This configuration integrates [Package-Name-Guardian](https://github.com/Silica-Proxy/Package-Name-Guardian), a package name analysis service that validates whether package names match internal naming conventions, detects typosquatting patterns, and flags suspicious naming anomalies across ecosystems. Run it in sync mode (blocking until resolved) with a 1-second timeout.

#### Available External Services

| Service | Purpose | Repository |
|---|---|---|
| **Package-Name-Guardian** | Validates package names against internal conventions; detects typosquatting and naming anomalies | [Silica-Proxy/Package-Name-Guardian](https://github.com/Silica-Proxy/Package-Name-Guardian) |

---

### 5. Live security API fallback — on-demand, configurable cache (Priority 3)

If a package passes the quarantine and deprecation checks but has no result in the local vulnerability tables, SilicaProxy queries external security APIs in order.

| Source | Notes |
|---|---|
| **OSV Live** (`api.osv.dev`) | Free, broad coverage — enabled by default, tried first |
| **deps.dev** (Google Open Source Insights) | Dependency graph and licence data — tried if OSV is disabled, or hands over to it on error |

Each source can be enabled or disabled independently (see [Configuration Reference](#configuration-reference)). The **first enabled source that answers successfully concludes the chain** — its verdict is cached in `api_cache` with configurable TTLs:
- **BLOCK verdicts** (vulnerability found): 10,080 minutes (7 days) — safe to cache longer
- **ALLOW verdicts** (no vulnerability): 1,440 minutes (24 hours) — shorter TTL for safety
- Can be independently disabled via `cache-allow-verdict: false`

**On error, the chain hands over instead of stopping:** a source that fails (HTTP error, timeout, network issue) does not conclude the chain — the next enabled source is tried instead. Only if *every* enabled source fails does the per-source [`fail-open`](#what-fail-open--fail-closed-means) policy decide the verdict (`silicaproxy.api-fallback.<source>.fail-open`, default `true`): ALLOW if every failed source is fail-open, BLOCK if at least one is fail-closed (the most restrictive result wins). This verdict is reported with `step: API_FALLBACK_ERROR` (see [API Endpoints](#api-endpoints)).

This error verdict is **deliberately never cached** — caching it would keep allowing (or blocking) the package for the whole TTL window even after the failing API recovers, turning a transient outage into a security hole (fail-open) or a needless block (fail-closed) that outlives the actual incident. The next request after recovery gets a fresh, real verdict.

**Next:** Configure your company-level policies in [GitOps policy files](#gitops-policy-files).

---

## Deployment

### Development

**Prerequisites:** Java 25+, Docker

```bash
# Start PostgreSQL + a local Gitea instance (auto-provisioned with sample policies)
docker compose up -d

# Run the proxy (connects to localhost:5432 by default)
./gradlew bootRun
```

The proxy listens on **port 8080**. Configure your artifact repository to route outbound traffic through `<host>:8080` (HTTP proxy type), then assign it to your npm, PyPI, and Maven remote repositories.

> **HTTPS repositories:** SilicaProxy performs SSL MITM. It generates a CA at startup that must be imported into your artifact repository's trust store. Retrieve it with:
> ```bash
> curl http://localhost:8089/api/monitoring/ca-cert > silicaproxy-ca.crt
> ```

---

### Production — Docker

Pre-built images are available on [Docker Hub](https://hub.docker.com/r/silicaproxy/silicaproxy).

```bash
docker build -t silicaproxy .
```

All configuration is passed as environment variables. Minimum required set:

```bash
docker run -d \
  -p 8080:8080 \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://your-db:5432/security_db \
  -e SPRING_DATASOURCE_USERNAME=prod_user \
  -e SPRING_DATASOURCE_PASSWORD=prod_password \
  -e SILICAPROXY_GITOPS_REPOSITORY_URL=https://git.yourcompany.com/devops/policies.git \
  -e SILICAPROXY_GITOPS_CLONE_TOKEN=yourtoken \
  -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/data/silicaproxy-ca.p12 \
  -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=changeme \
  -v /data/silicaproxy:/data \
  silicaproxy
```

> **CA keystore persistence:** without `-e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH`, a new CA is generated at every container restart — breaking your artifact repository's SSL trust until the certificate is re-imported. Mount a volume and set this variable in production.

---

### Production — Multiple instances / load balancing

All instances behind a load balancer **must use the same CA keystore file** — otherwise each one generates its own CA, and clients get random SSL trust failures depending which backend they land on.

**With shared storage** (NFS/EFS, a `ReadWriteMany` PVC, a bind-mounted volume): point every instance's `ca-keystore-path` at the same shared file. Instances can be started in any order, including all at once — CA generation is coordinated through a distributed lock (backed by the same PostgreSQL database every instance already uses, via the ShedLock table). Whichever instance starts first wins the lock, generates the CA and saves it; the others wait for the lock — or notice the file appear — and load it instead of generating their own. No staggered rollout is required.

**Without shared storage** (independent servers, no shared filesystem): the lock only protects instances that read and write the *same file* — with no shared file, it can't help, so generate the CA once and copy the same file everywhere.

1. Generate it with a throwaway instance against any reachable Postgres:
   ```bash
   docker run --rm -d --name ca-seed \
     -e SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/security_db \
     -e SPRING_DATASOURCE_USERNAME=postgres -e SPRING_DATASOURCE_PASSWORD=postgres \
     -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/data/silicaproxy-ca.p12 \
     -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=<strong-password> \
     -v "$(pwd)/ca-seed:/data" \
     silicaproxy
   docker rm -f ca-seed   # once it logged "CA certificate generated and saved"
   ```
2. Copy `ca-seed/silicaproxy-ca.p12` to the same path on every server (`scp`, config management, secrets manager), with the same `ca-keystore-password`. Never generate it again per-server.
3. Start SilicaProxy on each server pointing at the copied file — since it already exists, every instance loads it instead of generating its own.

Either way, back up the keystore file: losing it means every server mints a new, different CA on its next restart, breaking SSL trust everywhere until it's re-imported.

---

### Production — JAR

```bash
# Build
./gradlew bootJar
# Output: build/libs/silicaproxy.jar
```

Place an `application.yaml` next to the JAR (Spring Boot picks it up automatically), or point to it explicitly:

```bash
java \
  -XX:+UseZGC \
  -XX:MaxRAMPercentage=75.0 \
  -XX:+UseCompactObjectHeaders \
  -XX:+UseStringDeduplication \
  -Dsun.net.inetaddr.ttl=60 \
  -jar silicaproxy.jar \
  --spring.config.location=file:./application.yaml
```

Minimal `application.yaml` for production:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://your-db:5432/security_db
    username: prod_user
    password: prod_password

silicaproxy:
  gitops:
    repository-url: "https://git.yourcompany.com/devops/policies.git"
    clone-token: "yourtoken"
  ssl-mitm:
    ca-keystore-path: "/data/silicaproxy-ca.p12"
    ca-keystore-password: "changeme"
```

All other settings default to the values listed in the table below.

---

## Configuration Reference

Every YAML property can be overridden by an environment variable. Spring Boot's relaxed binding convention: replace dots and hyphens with `_`, uppercase everything (e.g. `silicaproxy.quarantine.fail-open` → `SILICAPROXY_QUARANTINE_FAIL_OPEN`).

### Full variable table

| Category | YAML property | Environment variable | Default | Description |
|---|---|---|---|---|
| **Database** | `spring.datasource.url` | `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/security_db` | PostgreSQL JDBC URL |
| | `spring.datasource.username` | `SPRING_DATASOURCE_USERNAME` | `postgres` | |
| | `spring.datasource.password` | `SPRING_DATASOURCE_PASSWORD` | `postgres` | |
| **Connection pool** | `spring.datasource.hikari.maximum-pool-size` | `HIKARI_MAX_POOL_SIZE` | `50` | Max DB connections |
| | `spring.datasource.hikari.minimum-idle` | `HIKARI_MIN_IDLE` | `15` | Min idle connections |
| | `spring.datasource.hikari.connection-timeout` | `HIKARI_CONNECTION_TIMEOUT` | `1500` | ms to wait for a connection |
| **Proxy** | `silicaproxy.proxy.port` | `SILICAPROXY_PROXY_PORT` | `8080` | Public TCP entry point |
| **Registries** | `silicaproxy.registries.npm-url` | `SILICAPROXY_REGISTRIES_NPM_URL` | `https://registry.npmjs.org` | npm registry base URL for metadata resolution |
| | `silicaproxy.registries.pypi-url` | `SILICAPROXY_REGISTRIES_PYPI_URL` | `https://pypi.org` | PyPI registry base URL for metadata resolution |
| | `silicaproxy.registries.maven-url` | `SILICAPROXY_REGISTRIES_MAVEN_URL` | `https://repo1.maven.org` | Maven Central base URL for metadata resolution |
| **Quarantine** | `silicaproxy.quarantine.enabled` | `SILICAPROXY_QUARANTINE_ENABLED` | `true` | Enable age-based quarantine globally |
| | `silicaproxy.quarantine.fail-open` | `SILICAPROXY_QUARANTINE_FAIL_OPEN` | `true` | Allow on registry error |
| | `silicaproxy.quarantine.default-min-age-days` | `SILICAPROXY_QUARANTINE_DEFAULT_MIN_AGE_DAYS` | `7` | Fallback threshold if not set per ecosystem |
| | `silicaproxy.quarantine.ecosystems.npm.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_NPM_ENABLED` | `true` | |
| | `silicaproxy.quarantine.ecosystems.npm.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_NPM_MIN_AGE_DAYS` | `7` | |
| | `silicaproxy.quarantine.ecosystems.pypi.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_PYPI_ENABLED` | `true` | |
| | `silicaproxy.quarantine.ecosystems.pypi.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_PYPI_MIN_AGE_DAYS` | `10` | |
| | `silicaproxy.quarantine.ecosystems.maven.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_MAVEN_ENABLED` | `false` | |
| | `silicaproxy.quarantine.ecosystems.maven.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_MAVEN_MIN_AGE_DAYS` | `5` | |
| **Deprecation** | `silicaproxy.deprecation.enabled` | `SILICAPROXY_DEPRECATION_ENABLED` | `true` | Block deprecated/yanked packages |
| | `silicaproxy.deprecation.ecosystems.npm` | `SILICAPROXY_DEPRECATION_ECOSYSTEMS_NPM` | `true` | |
| | `silicaproxy.deprecation.ecosystems.pypi` | `SILICAPROXY_DEPRECATION_ECOSYSTEMS_PYPI` | `true` | |
| **CVSS threshold** | `silicaproxy.severity-threshold.enabled` | `SILICAPROXY_SEVERITY_THRESHOLD_ENABLED` | `true` | |
| | `silicaproxy.severity-threshold.default-max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_DEFAULT_MAX_ALLOWED_SEVERITY` | `CRITICAL` | Severity level above which a package is blocked |
| | `silicaproxy.severity-threshold.default-max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_DEFAULT_MAX_ALLOWED_CVSS` | `7.0` | Score above which a package is blocked |
| | `silicaproxy.severity-threshold.ecosystems.npm.max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_NPM_MAX_ALLOWED_SEVERITY` | `HIGH` | |
| | `silicaproxy.severity-threshold.ecosystems.npm.max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_NPM_MAX_ALLOWED_CVSS` | `9.0` | |
| | `silicaproxy.severity-threshold.ecosystems.maven.max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_MAVEN_MAX_ALLOWED_SEVERITY` | `MEDIUM` | |
| | `silicaproxy.severity-threshold.ecosystems.maven.max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_MAVEN_MAX_ALLOWED_CVSS` | `7.0` | |
| | `silicaproxy.severity-threshold.ecosystems.pypi.max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_PYPI_MAX_ALLOWED_SEVERITY` | `MEDIUM` | |
| | `silicaproxy.severity-threshold.ecosystems.pypi.max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_PYPI_MAX_ALLOWED_CVSS` | `7.0` | |
| **API cache** | `silicaproxy.api-cache.cache-allow-verdict` | `SILICAPROXY_API_CACHE_CACHE_ALLOW_VERDICT` | `true` | Cache verdicts where no vulnerability found |
| | `silicaproxy.api-cache.block-verdict-ttl-minutes` | `SILICAPROXY_API_CACHE_BLOCK_VERDICT_TTL_MINUTES` | `10080` | Minutes to cache when vulnerability is found (7 days) |
| | `silicaproxy.api-cache.allow-verdict-ttl-minutes` | `SILICAPROXY_API_CACHE_ALLOW_VERDICT_TTL_MINUTES` | `1440` | Minutes to cache when no vulnerability found (24 hours) |
| **GitOps** | `silicaproxy.gitops.enabled` | `SILICAPROXY_GITOPS_ENABLED` | `true` | |
| | `silicaproxy.gitops.repository-url` | `SILICAPROXY_GITOPS_REPOSITORY_URL` | `http://localhost:3000/devops/policies.git` | URL of the policy Git repository |
| | `silicaproxy.gitops.directory-path` | `SILICAPROXY_GITOPS_DIRECTORY_PATH` | `policies/` | Subfolder inside the repo |
| | `silicaproxy.gitops.clone-token` | `SILICAPROXY_GITOPS_CLONE_TOKEN` | _(empty)_ | OAuth token or PAT for private repos |
| | `silicaproxy.gitops.sync-interval-minutes` | `SILICAPROXY_GITOPS_SYNC_INTERVAL_MINUTES` | `10` | |
| **SSL MITM** | `silicaproxy.ssl-mitm.ca-keystore-path` | `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH` | `./certs/ca.p12` | PKCS12 path — empty = ephemeral CA |
| | `silicaproxy.ssl-mitm.ca-keystore-password` | `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD` | _(empty)_ | Keystore password for encryption |
| | `silicaproxy.ssl-mitm.ca-cert-export-path` | `SILICAPROXY_SSL_MITM_CA_CERT_EXPORT_PATH` | `/tmp/silicaproxy-ca.crt` | Public CA certificate export path (PEM) |
| | `silicaproxy.ssl-mitm.context-cache-max-entries` | `SILICAPROXY_SSL_MITM_CONTEXT_CACHE_MAX_ENTRIES` | `2000` | Hard cap on the per-host SSLContext cache, on top of its 24h inactivity TTL — bounds the CPU/memory cost of CONNECT requests to many distinct hostnames |
| **Corporate proxy** | `silicaproxy.corporate-proxy.enabled` | `SILICAPROXY_CORPORATE_PROXY_ENABLED` | `false` | Route outbound traffic through a corporate proxy |
| | `silicaproxy.corporate-proxy.host` | `SILICAPROXY_CORPORATE_PROXY_HOST` | — | |
| | `silicaproxy.corporate-proxy.port` | `SILICAPROXY_CORPORATE_PROXY_PORT` | — | |
| | `silicaproxy.corporate-proxy.non-proxy-hosts` | `SILICAPROXY_CORPORATE_PROXY_NON_PROXY_HOSTS` | `localhost\|127.0.0.1` | Pipe-separated bypass list |
| | `silicaproxy.corporate-proxy.scope.registries` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_REGISTRIES` | `true` | Route registry traffic through proxy |
| | `silicaproxy.corporate-proxy.scope.security-apis` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_SECURITY_APIS` | `true` | Route security API traffic through proxy |
| | `silicaproxy.corporate-proxy.scope.external-git-repositories` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_EXTERNAL_GIT_REPOSITORIES` | `true` | Route vulnerability DB git clones through proxy |
| | `silicaproxy.corporate-proxy.scope.internal-git-repository` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_INTERNAL_GIT_REPOSITORY` | `false` | Route GitOps repo through proxy |
| **External validation** | `silicaproxy.external-validation.callback-base-url` | `SILICAPROXY_EXTERNAL_VALIDATION_CALLBACK_BASE_URL` | _(empty)_ | Base URL of this proxy instance — **required if any service uses `mode: async`**, and checked at startup: the proxy refuses to start rather than send a broken relative callback URL |
| | `silicaproxy.external-validation.trigger-async-on-sync-block` | `SILICAPROXY_EXTERNAL_VALIDATION_TRIGGER_ASYNC_ON_SYNC_BLOCK` | `false` | If true, async services are triggered even when a sync service already blocks |
| | `silicaproxy.external-validation.services.<name>.enabled` | — | `false` | Enable this external validation service |
| | `silicaproxy.external-validation.services.<name>.url` | — | — | HTTP endpoint to POST validation requests to |
| | `silicaproxy.external-validation.services.<name>.api-key` | — | _(empty)_ | Sent as `Authorization` header on outbound calls; for async services, also required back as `Authorization: Bearer {api-key}` on the callback if set (optional otherwise) |
| | `silicaproxy.external-validation.services.<name>.mode` | — | — | `sync` (wait for response) or `async` (fire-and-forget + callback) |
| | `silicaproxy.external-validation.services.<name>.timeout-seconds` | — | `1` | Max wait time in sync mode — on timeout, `fail-open` policy applies |
| | `silicaproxy.external-validation.services.<name>.fail-open` | — | `true` | `true` = allow on error/timeout/pending; `false` = block |
| | `silicaproxy.external-validation.services.<name>.blocking` | — | `true` | `false` = verdict stored for audit but never blocks a package |
| | `silicaproxy.external-validation.services.<name>.cache-ttl-minutes` | — | `0` ⚠️ | How long to cache an ALLOW verdict — **no implicit default, must be set explicitly** |
| | `silicaproxy.external-validation.services.<name>.pending-ttl-minutes` | — | `30` | Async only — how long to keep a PENDING entry before marking it TIMEOUT (falls back to 30 if unset or `0`) |
| | `silicaproxy.http-client.external-validation-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_EXTERNAL_VALIDATION_READ_TIMEOUT_SECONDS` | `1` | HTTP read timeout for calls to external validation services |
| | `silicaproxy.corporate-proxy.scope.external-validation` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_EXTERNAL_VALIDATION` | `false` | Route external validation traffic through the corporate proxy |
| **API call log** | `silicaproxy.api-call-log.enabled` | `SILICAPROXY_API_CALL_LOG_ENABLED` | `false` | Audit every live OSV/deps.dev call in `api_call_log` — **disabled by default, see warning below** |
| | `silicaproxy.api-call-log.flush-interval-seconds` | `SILICAPROXY_API_CALL_LOG_FLUSH_INTERVAL_SECONDS` | `30` | Batch flush interval (seconds) |
| | `silicaproxy.api-call-log.buffer-capacity` | `SILICAPROXY_API_CALL_LOG_BUFFER_CAPACITY` | `5000` | In-memory buffer size before entries are dropped |
| **OSV incremental** | `silicaproxy.osv-incremental.enabled` | `SILICAPROXY_OSV_INCREMENTAL_ENABLED` | `true` | Enable hourly incremental OSV sync |
| | `silicaproxy.osv-incremental.gcs-base-url` | `SILICAPROXY_OSV_INCREMENTAL_GCS_BASE_URL` | `https://storage.googleapis.com/osv-vulnerabilities` | GCS base URL for `modified_id.csv` files |
| | `silicaproxy.osv-incremental.initial-lookback-hours` | `SILICAPROXY_OSV_INCREMENTAL_INITIAL_LOOKBACK_HOURS` | `25` | Window fetched on first run (before any watermark) |
| **Fallback APIs** | `silicaproxy.api-fallback.osv.enabled` | `SILICAPROXY_API_FALLBACK_OSV_ENABLED` | `true` | Enable Google OSV Live API (free) |
| | `silicaproxy.api-fallback.osv.url` | — | `https://api.osv.dev/v1/query` | OSV API endpoint |
| | `silicaproxy.api-fallback.osv.fail-open` | `SILICAPROXY_API_FALLBACK_OSV_FAIL_OPEN` | `true` | Verdict when OSV fails **and** no later source in the chain concludes either (see [Live security API fallback](#5-live-security-api-fallback--on-demand-configurable-cache-priority-3)) |
| | `silicaproxy.api-fallback.deps-dev.enabled` | `SILICAPROXY_API_FALLBACK_DEPS_DEV_ENABLED` | `true` | Enable Google deps.dev API (free) |
| | `silicaproxy.api-fallback.deps-dev.url` | — | `https://api.deps.dev/v3/` | deps.dev API endpoint |
| | `silicaproxy.api-fallback.deps-dev.fail-open` | `SILICAPROXY_API_FALLBACK_DEPS_DEV_FAIL_OPEN` | `true` | Verdict when deps.dev fails **and** no later source in the chain concludes either |
| **HTTP timeouts** | `silicaproxy.http-client.connect-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_CONNECT_TIMEOUT_SECONDS` | `5` | |
| | `silicaproxy.http-client.registries-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_REGISTRIES_READ_TIMEOUT_SECONDS` | `60` | For binary downloads |
| | `silicaproxy.http-client.security-apis-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_SECURITY_APIS_READ_TIMEOUT_SECONDS` | `10` | For JSON security API calls |
| **SSRF protection** | `silicaproxy.security.ssrf-protection.enabled` | `SILICAPROXY_SECURITY_SSRF_PROTECTION_ENABLED` | `true` | Block outbound calls to loopback/private IPs |
| **API key auth** | `silicaproxy.security.api-auth.enabled` | `SILICAPROXY_SECURITY_API_AUTH_ENABLED` | `true` | Require a Bearer API key on internal admin/API endpoints (see [API Endpoints](#api-endpoints)) — set `false` only for local dev/tests |
| | `silicaproxy.security.api-auth.key-read` | `SILICAPROXY_API_KEY_READ` | _(empty)_ | Bearer key for read-only endpoints (consultation, no side effect) |
| | `silicaproxy.security.api-auth.key-action` | `SILICAPROXY_API_KEY_ACTION` | _(empty)_ | Bearer key for action endpoints (triggers a side effect, e.g. forced sync) — also grants access to `READ` endpoints |

> **Warning — API call log performance impact:** enabling `silicaproxy.api-call-log.enabled` generates one database row per package that reaches the live API fallback (OSV Live / deps.dev). In a busy CI/CD environment where many unknown packages are requested simultaneously, this can produce hundreds of writes per minute. Calls are buffered in memory and flushed in batches (configurable via `flush-interval-seconds`), so the write never blocks the security decision path. However, the underlying PostgreSQL table (`api_call_log`) will grow at the rate of live API calls, and partition maintenance (creating monthly partitions) must be planned. Only enable in production if you have a monitoring setup to track table growth.

> **Warning — `cache-ttl-minutes` has no implicit default:** if left unset for an external validation service, it binds to `0`, which means every cached ALLOW verdict is treated as already expired — the sync service is re-called (or, for an async ALLOWED callback, the next request re-triggers async validation) on **every single request** instead of being cached. Always set it explicitly for any service you configure. The startup log (see [Observability](#observability)) prints the effective value of every service, so a missing TTL is immediately visible.

---

### GitOps policy files

One YAML file per ecosystem (`policies/npm.yaml`, `policies/maven.yaml`, `policies/pypi.yaml`):

```yaml
rules:
  - package: "event-stream"
    version: "3.3.6"
    action: "block"
    reason: "Supply-chain attack (flatmap-stream, Nov 2018)"

  - package: "lodash"
    version: "*"
    action: "allow"
    reason: "Approved by architecture team"

  - package: "shelljs"
    version: "0.8.*"
    action: "block"
    reason: "Forbidden — use child_process directly"

  - package: "@compromised-scope/*"
    version: "*"
    action: "block"
    reason: "Entire npm scope compromised in a supply-chain attack"
```

#### Version patterns

| Written in YAML | Stored in DB | Matches |
|---|---|---|
| `1.0.0` | `1.0.0` | exact version only |
| `1.*` | `1.%` | any version starting with `1.` |
| `1.x` | `1.%` | same as `1.*` — npm-style trailing `.x`/`.X` segment |
| `*` | `%` | all versions |

`*` is always a wildcard, anywhere in the string. `x`/`X` is only treated as a wildcard as a
full **trailing** version segment (`1.2.x`, `4.X`) — a literal `x` elsewhere in the string
(e.g. a pre-release suffix like `1.0.0-xyz`) is left untouched, since real versions can
legitimately contain the letter.

#### Package name patterns

`package` also accepts a `*` wildcard, to apply one rule to a whole family of packages (e.g. an entire compromised scope) instead of listing every affected name individually:

| Written in YAML | Matches |
|---|---|
| `event-stream` | exact package name only |
| `@compromised-scope/*` | any package name starting with `@compromised-scope/` |
| `*` | all packages |

Unlike version patterns, the letter `x` is **not** treated as a wildcard in package names — only `*` is. Many real package names legitimately contain an `x` (`axios`, `next`, `xml2js`...), so interpreting it as a wildcard would cause unintended matches.

#### Conflict resolution when multiple rules match

When several rules match the same package/version, **the most specific pattern wins**, regardless of the action. An exact package name always beats a wildcard package pattern; the version pattern is only used as a tie-breaker between rules that have the same package specificity:

| Rules | Requested package / version | Winner | Outcome |
|---|---|---|---|
| `* → allow` + `1.0.0 → block` | `1.0.0` | `1.0.0` (exact) | 🚫 blocked |
| `* → allow` + `1.0.0 → block` | `2.0.0` | `*` | ✅ allowed |
| `* → block` + `1.0.0 → allow` | `1.0.0` | `1.0.0` (exact) | ✅ allowed |
| `* → block` + `1.0.0 → allow` | `2.0.0` | `*` | 🚫 blocked |
| `1.* → block` + `1.0.0 → allow` | `1.0.0` | `1.0.0` (exact) | ✅ allowed |
| `1.* → block` + `1.0.0 → allow` | `1.1.0` | `1.*` | 🚫 blocked |
| `@scope/* → block` + `@scope/pkg → allow` (any version) | `@scope/pkg` | `@scope/pkg` (exact package) | ✅ allowed |

This makes it possible to open a precise exception on a single version inside a globally blocked package (or a single package inside a globally blocked scope), and vice versa. If two rules end up with the **same specificity** (e.g. two different wildcard patterns that both match, neither more specific than the other by the rules above), the **most restrictive action wins deterministically**: `block` beats `allow` — the tie is never resolved by arbitrary row order.

#### Severity and CVSS thresholds

**Default behavior (if not configured):**
- `severity-threshold.enabled: true` (globally active)
- `default-max-allowed-severity: CRITICAL` → allows all severity levels globally (CRITICAL is the highest — severity-based blocking is driven by ecosystem overrides)
- `default-max-allowed-cvss: 7.0` → blocks CVSS > 7.0
- Ecosystem overrides: npm allows up to HIGH/9.0, maven/pypi allow up to MEDIUM/7.0

**When both are configured**, **both criteria must be satisfied** — the most restrictive threshold wins. A package is blocked if it violates either filter:

| Scenario | Severity threshold | CVSS threshold | Verdict |
|---|---|---|---|
| HIGH severity, CVSS 8.5 | `default-max-allowed-severity: CRITICAL` | `default-max-allowed-cvss: 7.0` | 🚫 BLOCK (CVSS > 7.0) |
| HIGH severity, CVSS 6.5 | `default-max-allowed-severity: CRITICAL` | `default-max-allowed-cvss: 7.0` | ✅ ALLOW |
| HIGH severity, CVSS 6.5 | `default-max-allowed-severity: MEDIUM` | `default-max-allowed-cvss: 7.0` | 🚫 BLOCK (severity > MEDIUM) |
| CRITICAL severity, CVSS 8.5 | `default-max-allowed-severity: CRITICAL` | `default-max-allowed-cvss: 9.0` | ✅ ALLOW |

The system computes a minimum CVSS floor from the severity level (e.g., `CRITICAL` → 9.0, `HIGH` → 7.0, `MEDIUM` → 4.0) and then takes the stricter of the two: `min(configured-cvss, severity-derived-cvss)`.

**To disable severity filtering entirely**, set `severity-threshold.enabled: false` — all packages pass the threshold check regardless of CVSS or severity score.

> Even when set to `false`, known malware (`id LIKE 'MAL-%'` or `source = 'OPENSSF'`) is still always blocked — this flag only disables severity/CVSS filtering for regular CVEs.

#### Malware always bypasses the severity/CVSS threshold

Entries from the **OpenSSF Malicious Packages** source (typosquatting, sabotage, known malware — see [Public vulnerabilities](#2-public-vulnerabilities--nightly-batch-sync--hourly-incremental-priority-2)) are not CVEs: they carry no CVSS vector or qualitative severity, since a package is malicious or it isn't — there's no "how severe" scale. Ingestion therefore assigns them a default `cvss_score` of `0.0`.

If the standard threshold logic applied as-is, a `0.0` score would always pass under `default-max-allowed-cvss` / `default-max-allowed-severity`, silently letting known-malicious packages through. To prevent this, `DecisionDao` adds an unconditional `OR` to the `public_vulnerabilities` lookup that ignores the configured thresholds entirely for these rows:

```sql
AND (cvss_score >= :minCvss::numeric OR id LIKE 'MAL-%' OR source = 'OPENSSF')
```

A row matches this bypass if its advisory `id` starts with `MAL-` (the OSV malware ID convention) **or** its `source` column is `OPENSSF`. Either one is always `BLOCK`, regardless of `severity-threshold.enabled` or any configured CVSS/severity value.

| Entry type | Severity/CVSS threshold applies? |
|---|---|
| CVE (OSV, GHSA, GitLab) | Yes — `min(configured-cvss, severity-derived-cvss)` |
| Malware (`MAL-*` id or `source = OPENSSF`) | No — always `BLOCK` |

---

## API Endpoints

Endpoints marked `READ` or `ACTION` in the **Auth** column require `Authorization: Bearer {key}`,
using `silicaproxy.security.api-auth.key-read` or `-key-action` respectively (see
[Configuration Reference](#full-variable-table)); a missing or wrong key returns `401`. `ACTION`
is a superset of `READ`: the action key also unlocks `READ` endpoints, but the read key never
unlocks `ACTION` ones. Set `silicaproxy.security.api-auth.enabled=false` to disable this check
entirely (local dev/tests only). The main proxy endpoint (`GET /**`), the external validation
callback (which has its own independent, per-service key — see below), and `/actuator/*` are
intentionally out of scope.

| Method | Auth | Description |
|---|---|---|
| `GET /**` | — | Proxy endpoint: streams the package or returns `403` |
| `GET /api/monitoring/health` | READ | Global health check (`UP` / `DEGRADED` / `DOWN`) |
| `GET /api/monitoring/ca-cert` | READ | CA certificate in PEM format — import into your artifact repository's trust store |
| `GET /api/vulnerabilities/sync/status` | READ | Sync job status + data inventory |
| `POST /api/vulnerabilities/sync/force` | ACTION | Trigger a manual vulnerability sync |
| `POST /api/gitops/sync/force` | ACTION | Trigger a manual GitOps policy sync |
| `GET /api/packages/search?packageName=&ecosystem=&version=` | READ | Diagnostic: look up a package in all local sources |
| `GET /api/policies/evaluate?ecosystem=&packageName=&version=` | READ | Evaluate which company policy rule applies to a given package |
| `POST /api/policies/simulate` | READ | Simulate a policy set against a package without persisting rules |
| `POST /external-validation/callback/{token}` | — | Async validation callback — called by external services to deliver a verdict |
| `GET /actuator/prometheus` | — | Prometheus metrics |

**Blocked package response (RFC 7807):**

```json
{
  "status": 403,
  "title": "Forbidden",
  "detail": "Blocked by company policy: shelljs is forbidden",
  "package": "shelljs",
  "version": "0.8.5",
  "ecosystem": "npm",
  "step": "COMPANY_POLICY"
}
```

The `step` field indicates which pipeline stage made the blocking decision:

| `step` value | Source |
|---|---|
| `COMPANY_POLICY` | GitOps YAML rule (blacklist) — checked first |
| `PUBLIC_VULN` | Local vulnerability database (OSV, GHSA, …) — CVSS-threshold block |
| `PUBLIC_VULN_MALWARE` | Local vulnerability database, `MAL-*` id or `source = OPENSSF` — always blocked regardless of CVSS |
| `API_CACHE` | Cached result from a previous live API call |
| `REGISTRY_ERROR` | Public registry unreachable and proxy configured fail-closed |
| `REGISTRY_DEPRECATION` | Package deprecated or yanked from its registry — checked before quarantine |
| `REGISTRY_QUARANTINE` | Package too recently published (anti-typosquatting) |
| `EXTERNAL_VALIDATION` | External validation service (sync or async) |
| `OSV_LIVE` | Google OSV live API — first fallback |
| `DEPS_DEV` | Google deps.dev live API — tried if OSV is disabled, or after OSV errors |
| `API_FALLBACK_ERROR` | Every enabled live API fallback source failed — verdict decided by [`fail-open`](#what-fail-open--fail-closed-means), never cached |

---

## Observability

- **Prometheus metrics** at `/actuator/prometheus` (SQL latency, package verdict counters, HikariCP pool stats) — see [Metrics](#metrics) for the full list.
- **External validation startup log** (`INFO`): on boot, every configured external validation service is logged with its effective settings (`enabled`, `mode`, `url`, `blocking`, `failOpen`, `timeoutSeconds`, `cacheTtlMinutes`) — use this to catch a missing/wrong value (e.g. an unset `cache-ttl-minutes`, see [Configuration Reference](#full-variable-table)) without reading the YAML/env back out of the running container.
- **External validation callback log** (`INFO`): every async callback received at `POST /external-validation/callback/{token}` logs the originating service, package, and verdict before it's applied.
- **Sync progress** visible in `/api/vulnerabilities/sync/status` with per-job `progressPercent`.

---

## Recommended JVM flags (production)

```
-XX:+UseZGC
-XX:MaxRAMPercentage=75.0
-XX:+UseCompactObjectHeaders
-XX:+UseStringDeduplication
-Dsun.net.inetaddr.ttl=60
```

---

## Recommended PostgreSQL configuration (production)

SilicaProxy's default HikariCP pool is **50 connections**. Tune PostgreSQL to match:

```sql
-- postgresql.conf — size these for your hardware
max_connections = 100                     -- 2× HikariCP maximum-pool-size (buffer for admin ops)
shared_buffers = 0.25 × system_RAM        -- E.g. 4GB on 16GB server
effective_cache_size = 0.75 × system_RAM  -- E.g. 12GB on 16GB server; hints query planner

-- Per-query memory (sort, hash join)
work_mem = 0.5 × (effective_cache_size / max_connections)  -- E.g. 60MB on 16GB/100 conns

-- Tune for your storage
effective_io_concurrency = 50             -- HDDs; raise to 100–200 for SSD/NVMe
random_page_cost = 4.0                    -- HDD default; lower to 1.0–1.5 for SSD

-- Vacuum (tables inherit aggressive defaults for api_cache cleanup)
autovacuum = on
autovacuum_max_workers = 2
autovacuum_naptime = 10s

-- Logging
log_min_duration_statement = 1000         -- Log queries slower than 1s
```

The `api_cache` table already has tuned autovacuum (5% scale factor, 100-row threshold) for aggressive cache cleanup.

## Metrics

All custom metrics are exposed via Micrometer at `GET /actuator/prometheus`, alongside the standard JVM/HikariCP/Tomcat metrics. Tag values are always bounded, config-driven enum-like strings (never raw package names, versions, or free-text reasons), so cardinality stays safe for Prometheus.

Metric names, tag keys, and tag values are all defined once in `com.silicaproxy.config.Metrics` — the single source of truth referenced by every producer and every test assertion below.

**Proxy decisions**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.controller.decisions` | Counter | `verdict` (`ALLOW`/`BLOCK`/`WHITELIST`/`BLACKLIST`), `source` (`COMPANY_POLICY`, `PUBLIC_VULN`, `PUBLIC_VULN_MALWARE`, `API_CACHE`, `REGISTRY_QUARANTINE`, `REGISTRY_DEPRECATION`, `REGISTRY_ERROR`, `EXTERNAL_VALIDATION`, `OSV_LIVE`, `DEPS_DEV`, `DEFAULT`), `ecosystem` | Every finalized proxy decision. Sum for total analyses; filter by `verdict` for allow/block counts; filter by `source` for the reason breakdown. |
| `silicaproxy.controller.security.bypass` | Counter | `ecosystem` | Requests that skipped `SecurityService` entirely (unparseable URL or direct-resource request) — the proxy's security blind spot. |
| `silicaproxy.controller.security.overhead` | Timer | `decision` (`block`/`allow`) | Duration of the security check only, excluding binary streaming. |
| `silicaproxy.decision.local_evaluation` | Counter | `outcome` (`HIT`/`MISS`) | Whether `DecisionDao`'s single SQL query (company policy / public vulnerability / `api_cache`) resolved the verdict without an external call (`HIT`), or a registry/OSV/deps.dev round trip was required (`MISS`). |

**External vulnerability APIs (OSV live fallback, deps.dev)**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.external.api.calls` | Counter | `source` (`OSV_LIVE`/`DEPS_DEV`), `result` (`ALLOW`/`BLOCK`/`ERROR`) | Calls to the live fallback vulnerability APIs, by outcome. |

**External validation services**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.external.validation.calls` | Counter | `service`, `type` (`sync`/`async`), `result` (`ALLOWED`/`BLOCKED`/`ERROR`/`UNKNOWN_VERDICT`/`TRIGGERED`/`TRIGGER_ERROR`) | Every sync call result and every async trigger/callback verdict, per configured service. |
| `silicaproxy.external.validation.block_reason` | Counter | `reason` (`VERDICT`/`FAIL_CLOSED`) | Distinguishes a genuine malicious verdict from a package merely blocked because a blocking service was unavailable/slow (fail-closed) — an infra incident, not a real threat. |
| `silicaproxy.external.validation.callback` | Counter | `service`, `result` (`PROCESSED`/`NOT_FOUND`/`UNAUTHORIZED`) | Every request to `POST /external-validation/callback/{token}`. `NOT_FOUND`/`UNAUTHORIZED` surface replay attempts, stale/duplicate deliveries, or a misconfigured API key. |

**Vulnerability sync (OSV incremental)**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.vulnerability.sync.advisories` | Counter | `ecosystem`, `outcome` (`PROCESSED`/`FAILED`) | Advisory IDs handled per incremental sync run. |
| `silicaproxy.vulnerability.sync.records` | Counter | `ecosystem`, `outcome` (`INSERTED`/`UPDATED`) | Rows written to `public_vulnerabilities`. |
| `silicaproxy.vulnerability.sync.seconds_since_last_success` | Gauge | `ecosystem` | Time since the last successful incremental sync run — detects a silently stalled job. |

**GitOps policy sync**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.gitops.sync.policies` | Counter | `ecosystem` | `company_policies` rows synchronized from the GitOps repository. |
| `silicaproxy.gitops.sync.runs` | Counter | `outcome` (`SUCCESS`/`FAILURE`) | Sync run outcomes. |
| `silicaproxy.gitops.sync.seconds_since_last_success` | Gauge | — | Time since the last successful GitOps sync run. |

---


---

## Attribution Requirement
If you use SilicaProxy in your project, product, or service, you **must** include the following attribution in a visible location (e.g., UI footer, documentation, or "About" page):

> "Secured by SilicaProxy (https://github.com/Silica-Proxy/Silica-Proxy)"

This is a **binding requirement** of the [Apache 2.0 License](LICENSE).

## Disclaimer
SilicaProxy is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software, its use, or any collateral damage (including but not limited to server downtime, data loss, or system bugs) resulting from the use of this software.
By using SilicaProxy, you agree to these terms and use this tool entirely at your own risk.


## License

[Apache License 2.0](LICENSE)
