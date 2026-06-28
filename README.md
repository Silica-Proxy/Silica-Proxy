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
         │ Live API fallback     │  OSV → deps.dev
         └───────────────────────┘
                     │
              ALLOW → stream package to client
              BLOCK → HTTP 403 (RFC 7807 JSON)
```

### Package structure

The codebase is organized around the detection phases a request goes through:

```
fr.silicaproxy
├── controller/           REST endpoints (proxy, GitOps, policies, monitoring, search)
├── service/
│   ├── interception/     TCP entry point, SSL MITM, URL/ecosystem parsing
│   ├── policy/           Company policy evaluation, GitOps sync
│   ├── vulnerability/    CVE ingestion, OSV incremental sync, scheduler
│   ├── decision/         SecurityService orchestrator, api_cache cleanup
│   ├── audit/            Async audit log
│   ├── monitoring/       Health checks, data inventory
│   └── search/           Package search
├── dao/
│   ├── policy/           SQL — company_policies, decision cache, metadata cache
│   ├── vulnerability/    SQL — public_vulnerabilities
│   ├── sync/             SQL — sync_status, sync_run_history, shedlock, health
│   ├── audit/            SQL — proxy_audit_logs, api_call_log
│   └── client/           HTTP — OSV, deps.dev, registry, Git, proxy stream
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

### 4. Live security API fallback — on-demand, configurable cache (Priority 3)

If a package passes the quarantine and deprecation checks but has no result in the local vulnerability tables, SilicaProxy queries external security APIs in order. The **first conclusive answer wins**; subsequent sources are skipped.

| Source | Notes |
|---|---|
| **OSV Live** (`api.osv.dev`) | Free, broad coverage — enabled by default |
| **deps.dev** (Google Open Source Insights) | Dependency graph and licence data |

Each source can be enabled or disabled independently (see [Configuration Reference](#configuration-reference)). Results are cached in `api_cache` table with configurable TTLs:
- **BLOCK verdicts** (vulnerability found): 10,080 minutes (7 days) — safe to cache longer
- **ALLOW verdicts** (no vulnerability): 1,440 minutes (24 hours) — shorter TTL for safety
- Can be independently disabled via `cache-allow-verdict: false`

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

### Production — JAR

```bash
# Build
./gradlew bootJar
# Output: build/libs/silicaproxy.jar
```

Place an `application.yaml` next to the JAR (Spring Boot picks it up automatically), or point to it explicitly:

```bash
java \
  -XX:+UseZGC -XX:+ZGenerational \
  -XX:MaxRAMPercentage=75.0 \
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
| | `silicaproxy.quarantine.ecosystems.npm.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_NPM_ENABLED` | `false` | |
| | `silicaproxy.quarantine.ecosystems.npm.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_NPM_MIN_AGE_DAYS` | `7` | |
| | `silicaproxy.quarantine.ecosystems.pypi.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_PYPI_ENABLED` | `true` | |
| | `silicaproxy.quarantine.ecosystems.pypi.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_PYPI_MIN_AGE_DAYS` | `10` | |
| | `silicaproxy.quarantine.ecosystems.maven.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_MAVEN_ENABLED` | `false` | |
| | `silicaproxy.quarantine.ecosystems.maven.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_MAVEN_MIN_AGE_DAYS` | `5` | |
| **Deprecation** | `silicaproxy.deprecation.enabled` | `SILICAPROXY_DEPRECATION_ENABLED` | `true` | Block deprecated/yanked packages |
| | `silicaproxy.deprecation.ecosystems.npm` | `SILICAPROXY_DEPRECATION_ECOSYSTEMS_NPM` | `true` | |
| | `silicaproxy.deprecation.ecosystems.pypi` | `SILICAPROXY_DEPRECATION_ECOSYSTEMS_PYPI` | `true` | |
| **CVSS threshold** | `silicaproxy.severity-threshold.enabled` | `SILICAPROXY_SEVERITY_THRESHOLD_ENABLED` | `true` | |
| | `silicaproxy.severity-threshold.default-max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_DEFAULT_MAX_ALLOWED_SEVERITY` | `MEDIUM` | Severity level above which a package is blocked |
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
| **SSL MITM** | `silicaproxy.ssl-mitm.ca-keystore-path` | `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH` | _(empty)_ | PKCS12 path — empty = ephemeral CA |
| | `silicaproxy.ssl-mitm.ca-keystore-password` | `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD` | _(empty)_ | Keystore password for encryption |
| | `silicaproxy.ssl-mitm.ca-cert-export-path` | `SILICAPROXY_SSL_MITM_CA_CERT_EXPORT_PATH` | `/tmp/silicaproxy-ca.crt` | Public CA certificate export path (PEM) |
| **Corporate proxy** | `silicaproxy.corporate-proxy.enabled` | `SILICAPROXY_CORPORATE_PROXY_ENABLED` | `false` | Route outbound traffic through a corporate proxy |
| | `silicaproxy.corporate-proxy.host` | `SILICAPROXY_CORPORATE_PROXY_HOST` | — | |
| | `silicaproxy.corporate-proxy.port` | `SILICAPROXY_CORPORATE_PROXY_PORT` | — | |
| | `silicaproxy.corporate-proxy.non-proxy-hosts` | `SILICAPROXY_CORPORATE_PROXY_NON_PROXY_HOSTS` | `localhost\|127.0.0.1` | Pipe-separated bypass list |
| | `silicaproxy.corporate-proxy.scope.registries` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_REGISTRIES` | `true` | Route registry traffic through proxy |
| | `silicaproxy.corporate-proxy.scope.security-apis` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_SECURITY_APIS` | `true` | Route security API traffic through proxy |
| | `silicaproxy.corporate-proxy.scope.external-git-repositories` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_EXTERNAL_GIT_REPOSITORIES` | `true` | Route vulnerability DB git clones through proxy |
| | `silicaproxy.corporate-proxy.scope.internal-git-repository` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_INTERNAL_GIT_REPOSITORY` | `false` | Route GitOps repo through proxy |
| **API call log** | `silicaproxy.api-call-log.enabled` | `SILICAPROXY_API_CALL_LOG_ENABLED` | `false` | Audit every live OSV/deps.dev call in `api_call_log` — **disabled by default, see warning below** |
| | `silicaproxy.api-call-log.flush-interval-seconds` | `SILICAPROXY_API_CALL_LOG_FLUSH_INTERVAL_SECONDS` | `30` | Batch flush interval (seconds) |
| | `silicaproxy.api-call-log.buffer-capacity` | `SILICAPROXY_API_CALL_LOG_BUFFER_CAPACITY` | `5000` | In-memory buffer size before entries are dropped |
| **OSV incremental** | `silicaproxy.osv-incremental.enabled` | `SILICAPROXY_OSV_INCREMENTAL_ENABLED` | `true` | Enable hourly incremental OSV sync |
| | `silicaproxy.osv-incremental.gcs-base-url` | `SILICAPROXY_OSV_INCREMENTAL_GCS_BASE_URL` | `https://storage.googleapis.com/osv-vulnerabilities` | GCS base URL for `modified_id.csv` files |
| | `silicaproxy.osv-incremental.initial-lookback-hours` | `SILICAPROXY_OSV_INCREMENTAL_INITIAL_LOOKBACK_HOURS` | `25` | Window fetched on first run (before any watermark) |
| **Fallback APIs** | `silicaproxy.api-fallback.osv.enabled` | `SILICAPROXY_API_FALLBACK_OSV_ENABLED` | `true` | Enable Google OSV Live API (free) |
| | `silicaproxy.api-fallback.osv.url` | — | `https://api.osv.dev/v1/query` | OSV API endpoint |
| | `silicaproxy.api-fallback.deps-dev.enabled` | `SILICAPROXY_API_FALLBACK_DEPS_DEV_ENABLED` | `false` | Enable Google deps.dev API (free) |
| | `silicaproxy.api-fallback.deps-dev.url` | — | `https://api.deps.dev/v3/` | deps.dev API endpoint |
| **HTTP timeouts** | `silicaproxy.http-client.connect-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_CONNECT_TIMEOUT_SECONDS` | `5` | |
| | `silicaproxy.http-client.registries-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_REGISTRIES_READ_TIMEOUT_SECONDS` | `60` | For binary downloads |
| | `silicaproxy.http-client.security-apis-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_SECURITY_APIS_READ_TIMEOUT_SECONDS` | `10` | For JSON security API calls |
| **SSRF protection** | `silicaproxy.security.ssrf-protection.enabled` | `SILICAPROXY_SECURITY_SSRF_PROTECTION_ENABLED` | `true` | Block outbound calls to loopback/private IPs |

> **Warning — API call log performance impact:** enabling `silicaproxy.api-call-log.enabled` generates one database row per package that reaches the live API fallback (OSV Live / deps.dev). In a busy CI/CD environment where many unknown packages are requested simultaneously, this can produce hundreds of writes per minute. Calls are buffered in memory and flushed in batches (configurable via `flush-interval-seconds`), so the write never blocks the security decision path. However, the underlying PostgreSQL table (`api_call_log`) will grow at the rate of live API calls, and partition maintenance (creating monthly partitions) must be planned. Only enable in production if you have a monitoring setup to track table growth.

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
```

#### Version patterns

| Written in YAML | Stored in DB | Matches |
|---|---|---|
| `1.0.0` | `1.0.0` | exact version only |
| `1.*` | `1.%` | any version starting with `1.` |
| `*` | `%` | all versions |

#### Conflict resolution when multiple rules match

When several rules match the same package/version, **the most specific pattern wins**, regardless of the action:

| Rules | Requested version | Winner | Outcome |
|---|---|---|---|
| `* → allow` + `1.0.0 → block` | `1.0.0` | `1.0.0` (exact) | 🚫 blocked |
| `* → allow` + `1.0.0 → block` | `2.0.0` | `*` | ✅ allowed |
| `* → block` + `1.0.0 → allow` | `1.0.0` | `1.0.0` (exact) | ✅ allowed |
| `* → block` + `1.0.0 → allow` | `2.0.0` | `*` | 🚫 blocked |
| `1.* → block` + `1.0.0 → allow` | `1.0.0` | `1.0.0` (exact) | ✅ allowed |
| `1.* → block` + `1.0.0 → allow` | `1.1.0` | `1.*` | 🚫 blocked |

This makes it possible to open a precise exception on a single version inside a globally blocked package, and vice versa. If two wildcard patterns of different breadth (`*` and `1.*`) conflict without an exact rule, the result is undefined — add an exact version rule to resolve it.

#### Severity and CVSS thresholds

**Default behavior (if not configured):**
- `severity-threshold.enabled: true` (globally active)
- `default-max-allowed-severity: MEDIUM` → blocks HIGH and CRITICAL
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

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET /**` | — | Proxy endpoint: streams the package or returns `403` |
| `GET /api/monitoring/health` | — | Global health check (`UP` / `DEGRADED` / `DOWN`) |
| `GET /api/monitoring/ca-cert` | — | CA certificate in PEM format — import into your artifact repository's trust store |
| `GET /api/vulnerabilities/sync/status` | — | Sync job status + data inventory |
| `POST /api/vulnerabilities/sync/force` | — | Trigger a manual vulnerability sync |
| `POST /api/gitops/sync/force` | — | Trigger a manual GitOps policy sync |
| `GET /api/packages/search?packageName=&ecosystem=&version=` | — | Diagnostic: look up a package in all local sources |
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

---

## Observability

- **Prometheus metrics** at `/actuator/prometheus` (SQL latency, package verdict counters, HikariCP pool stats).
- **Structured JSON logs** for every `403` event.
- **Webhook alerts** (Slack / Teams) for critical detections (manual blacklist or known malware).
- **Sync progress** visible in `/api/vulnerabilities/sync/status` with per-job `progressPercent`.

---

## Recommended JVM flags (production)

```
-XX:+UseZGC -XX:+ZGenerational
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

---

## Attribution Requirement
If you use SilicaProxy in your project, product, or service, you **must** include the following attribution in a visible location (e.g., UI footer, documentation, or "About" page):

> "Secured by SilicaProxy (https://github.com/Silica-Proxy/silicaproxy)"

This is a **binding requirement** of the [Apache 2.0 License](LICENSE).

## Disclaimer
SilicaProxy is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software, its use, or any collateral damage (including but not limited to server downtime, data loss, or system bugs) resulting from the use of this software.
By using SilicaProxy, you agree to these terms and use this tool entirely at your own risk.



## License

[Apache License 2.0](LICENSE)
