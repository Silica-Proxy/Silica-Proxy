# Observability

- **Prometheus metrics** at `/actuator/prometheus` (SQL latency, package verdict counters, HikariCP pool stats) — see [Metrics](#metrics) for the full list.
- **External validation startup log** (`INFO`): on boot, every configured external validation service is logged with its effective settings (`enabled`, `mode`, `url`, `blocking`, `failOpen`, `timeoutSeconds`, `cacheTtlMinutes`, `headCheck`) — use this to catch a missing/wrong value (e.g. a `cache-ttl-minutes` of `0`, which disables caching) without reading the YAML/env back out of the running container.
- **External validation callback log** (`INFO`): every async callback received at `POST /external-validation/callback/{token}` logs the originating service, package, and verdict before it's applied.
- **Sync progress** visible in `/api/vulnerabilities/sync/status` with per-job `progressPercent`.

## Health probes

The liveness and readiness probes never depend on a background synchronization: a failed sync
(gitlab.com outage, GCS timeout…) leaves the decisions running on the data already in the
database, so it must not take the proxy out of the load balancer.

| URL | Components | Use it for |
|---|---|---|
| `/actuator/health/liveness` | `livenessState`, `ping` | Kubernetes `livenessProbe` — the JVM is alive. Does not check the database: a restart would not fix it |
| `/actuator/health/readiness` | `readinessState`, `db`, `ping` | Kubernetes `readinessProbe`, load balancer health check — `DOWN` (HTTP `503`) when PostgreSQL is unreachable |
| `/actuator/health/sync` | `vulnerabilitySync`, `osvIncrementalSync`, `gitopsSync`, `caCertificate` | Monitoring / alerting only, never a probe |
| `/actuator/health` | all of the above (plus the `database` component) | Overview; prefer the groups above for probes |

Status rules of the sync components:

- A failed, missing or late job (GHSA, OpenSSF, GitLab, OSV zip, OSV incremental, GitOps) is
  `DEGRADED`, answered with HTTP `200`.
- `vulnerabilitySync` is `DOWN` (HTTP `503`) only when **no** OSV source — nightly zip or hourly
  incremental — has succeeded for `silicaproxy.health.osv-max-staleness-hours` (default `48`).
  A fresh install whose first sync has not succeeded yet (pending, running or failed) is never `DOWN`.
- `caCertificate` is `DEGRADED` within 30 days of its expiry, `DOWN` once expired.

Kubernetes example (the actuator answers on `server.port`, `8089` by default):

```yaml
livenessProbe:
  httpGet:
    path: /actuator/health/liveness
    port: 8089
  initialDelaySeconds: 30
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /actuator/health/readiness
    port: 8089
  periodSeconds: 5
  failureThreshold: 3
```

## Client identity in the audit log

Each verdict written to `proxy_audit_logs` records who downloaded the package, so that a package
allowed then flagged (malware) can be traced back to the affected workstations or CI runners:

| Column | Source |
|---|---|
| `client_ip` | Socket peer address of the client. `X-Forwarded-For` is only honoured when that peer is listed in `silicaproxy.proxy.trusted-proxies` : the right-most hop that is not a trusted proxy is recorded (left-most ones are writable by any client) |
| `user_agent` | `User-Agent` header (`npm/10.x`, `pip/24`, `Apache-Maven/3.9`…), truncated to 512 characters |
| `client_id` | Optional `X-Silica-Client` header (CI runner, project…), else the username of a `Basic` `Proxy-Authorization` (sent on the `CONNECT` for HTTPS). The password is never stored |

Behind a repository manager, these columns identify the repository manager, not the end client:
Artifactory remote repositories and Nexus 3 proxy repositories fetch from SilicaProxy with their own
HTTP client, on a cache miss only, and relay neither the client address, nor `X-Forwarded-For`, nor
its `User-Agent` (they send `Artifactory/7.x` / `Nexus/3.x`). They can still tag their requests:
an Artifactory remote repository accepts static custom headers (e.g. `X-Silica-Client: npm-remote`),
Nexus 3 a global User-Agent suffix (*System > HTTP*). Per-workstation identity requires the clients
to use SilicaProxy directly as their HTTP(S) proxy (or through an HTTP reverse proxy listed in
`trusted-proxies`); inside an HTTPS tunnel, only the `CONNECT`'s `Proxy-Authorization` username is
available, since no intermediate proxy can add `X-Forwarded-For` to encrypted traffic.

---

## Recommended JVM flags (production)

Give the container (or host) **at least 2 GB of memory**. `MaxRAMPercentage=75.0` sizes the heap from the container limit, and the remaining 25% must cover metaspace, code cache, thread stacks, network buffers and JGit — below 2 GB that headroom is too small during vulnerability sync (OSV ingestion + advisory Git clones), and the JVM ends up swapping or crashing.

```
-XX:+UseG1GC
-XX:MaxRAMPercentage=75.0
-XX:+UseCompactObjectHeaders
-XX:+UseStringDeduplication
-Dsun.net.inetaddr.ttl=60
```

The Docker image sets these flags through `JDK_JAVA_OPTIONS` (plus `-XX:ErrorFile=/app/logs/hs_err_pid%p.log` and `-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/app/logs`, so JVM crash reports and heap dumps survive a restart when `/app/logs` is a volume). Override the variable to change them — it replaces the defaults entirely:

```bash
docker run -d \
  -e JDK_JAVA_OPTIONS="-XX:+UseG1GC -XX:MaxRAMPercentage=60.0 -XX:+UseCompactObjectHeaders -Dsun.net.inetaddr.ttl=60" \
  ... \
  silicaproxy/silicaproxy
```

---

## Recommended PostgreSQL configuration (production)

SilicaProxy's default HikariCP pool is **70 connections** (up to 20 of them used by the audit log writers under load). Tune PostgreSQL to match:

```sql
-- postgresql.conf — size these for your hardware
max_connections = 140                     -- 2× HikariCP maximum-pool-size (buffer for admin ops)
shared_buffers = 0.25 × system_RAM        -- E.g. 4GB on 16GB server
effective_cache_size = 0.75 × system_RAM  -- E.g. 12GB on 16GB server; hints query planner

-- Per-query memory (sort, hash join)
work_mem = 0.5 × (effective_cache_size / max_connections)  -- E.g. 43MB on 16GB/140 conns

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
| `silicaproxy.controller.decisions` | Counter | `verdict` (`ALLOW`/`BLOCK`), `source` (`COMPANY_POLICY`, `PUBLIC_VULN`, `PUBLIC_VULN_MALWARE`, `PUBLIC_VULN_ANOMALY`, `API_CACHE`, `REGISTRY_QUARANTINE`, `REGISTRY_DEPRECATION`, `REGISTRY_ERROR`, `UPSTREAM_THROTTLED`, `REGISTRY_NOT_FOUND`, `UNIDENTIFIED_ARTIFACT`, `EXTERNAL_VALIDATION`, `EXTERNAL_VALIDATION_PENDING`, `EXTERNAL_VALIDATION_UNAVAILABLE`, `OSV_LIVE`, `DEPS_DEV`, `API_FALLBACK_ERROR`, `DEFAULT`), `ecosystem` | Every finalized proxy decision. Sum for total analyses; filter by `verdict` for allow/block counts; filter by `source` for the reason breakdown. |
| `silicaproxy.controller.security.bypass` | Counter | `ecosystem` | Requests that skipped `SecurityService` entirely. With a known `ecosystem`, this is expected metadata/index traffic (packuments, simple index, `maven-metadata.xml`…); `ecosystem="unknown"` is the proxy's security blind spot and should stay at 0. |
| `silicaproxy.identification.response` | Counter | `outcome` (`identified_from_database`/`identified`/`not_found`/`ambiguous`/`unavailable`/`skipped`) | Identification attempts from the upstream response digest ([details](package-identification.md#identification-from-the-upstream-response)). `identified_from_database` : found in `file_digest_index`, no deps.dev call; `identified` : found by deps.dev (then stored); `skipped` : not a package file or no usable digest announced. |
| `silicaproxy.identification.checksum.mismatch` | Counter | `ecosystem` | Downloads identified from their announced digest whose body did not match it — the download was cut. Any increase deserves an investigation of the upstream. |
| `silicaproxy.controller.security.overhead` | Timer | `decision` (`block`/`allow`) | Duration of the security check only, excluding binary streaming. |
| `silicaproxy.decision.local_evaluation` | Counter | `outcome` (`HIT`/`MISS`) | Whether `DecisionDao`'s single SQL query (company policy / public vulnerability / `api_cache`) resolved the verdict without an external call (`HIT`), or a registry/OSV/deps.dev round trip was required (`MISS`). |

**Quarantine publication date**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.quarantine.publish_date.lookups` | Counter | `ecosystem`, `source` (`PUBLIC_REGISTRY`/`ORIGIN_REGISTRY`/`LOCAL_CACHE`/`LOCAL_CACHE_NO_LOOKUP`/`UNRESOLVED`) | Where the publication date used by the quarantine check came from. `ORIGIN_REGISTRY` (npm only) means the public registry did not know the version and the registry the client resolved against was trusted instead; `LOCAL_CACHE` means the registry could not answer but the date was already known; `LOCAL_CACHE_NO_LOOKUP` means the registry was not queried at all, the cached date being enough (still quarantined, or no deprecation check for the ecosystem). |
| `silicaproxy.quarantine.publish_date.unresolved` | Counter | `ecosystem`, `verdict` (`ALLOW`/`BLOCK`) | Packages whose publication date could not be resolved, with the verdict applied by `silicaproxy.quarantine.fail-open`. With the default fail-open, each `ALLOW` is a package that **skipped the quarantine**: alert on it, e.g. `increase(silicaproxy_quarantine_publish_date_unresolved_total{verdict="ALLOW"}[1h]) > 0`. |

**Upstream rate limiting**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.upstream.throttled` | Counter | `host` (a configured registry / security API host, or `other`), `origin` (`RELAY`/`REGISTRY`/`SECURITY_API`), `outcome` (`RESPONSE`/`SUSPENDED`) | `RESPONSE` : the host answered 429; `SUSPENDED` : the call was not sent because the host is still suspended. |
| `silicaproxy.upstream.suspended_hosts` | Gauge | — | Hosts currently left alone after a 429. Alert when it stays above 0, e.g. `max_over_time(silicaproxy_upstream_suspended_hosts[5m]) > 0`. |

**External vulnerability APIs (OSV live fallback, deps.dev)**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.external.api.calls` | Counter | `source` (`OSV_LIVE`/`DEPS_DEV`), `result` (`ALLOW`/`BLOCK`/`ERROR`) | Calls to the live fallback vulnerability APIs, by outcome. |

**External validation services**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.external.validation.calls` | Counter | `service`, `type` (`sync`/`async`), `result` (`ALLOWED`/`BLOCKED`/`ERROR`/`UNKNOWN_VERDICT`/`TRIGGERED`/`TRIGGER_ERROR`) | Every sync call result and every async trigger/callback verdict, per configured service. |
| `silicaproxy.external.validation.block_reason` | Counter | `reason` (`VERDICT`/`PENDING`/`UNAVAILABLE`) | Distinguishes a genuine malicious verdict from a package only blocked temporarily by a fail-closed service: scan still running (`PENDING`), or service unavailable/slow (`UNAVAILABLE`) — an infra incident, not a real threat. |
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

**Proxy internals**

| Metric | Type | Tags | Description |
|---|---|---|---|
| `silicaproxy.ssl.mitm.ca.seconds_until_expiry` | Gauge | — | Seconds until the MITM CA certificate expires (`NaN` until the CA is initialized). Alert well before it reaches 0: every artifact repository that trusts the CA must import the new one. |
| `silicaproxy.service.auditlog.writes` | Counter | `outcome` (`SUCCESS`/`FAILURE`/`DROPPED`) | Audit log write attempts. `DROPPED` : the audit queue was full and the entry was discarded (downloads are never slowed down by the audit log). |
| `silicaproxy.loom.ssl.handshake` | Timer | — | Duration of the TLS MITM handshake, with p50/p90/p95/p99. |
| `silicaproxy.controller.requests` | Timer | — | Total processing time of a proxied request, with p50/p90/p95/p99. |
| `silicaproxy.service.*`, `silicaproxy.dao.*` | Timer | — | One timer per instrumented service method, SQL query and outbound HTTP call (e.g. `silicaproxy.dao.decision.evaluatedecision`, `silicaproxy.dao.registry.fetchmetadata`), with p50/p90/p95/p99. Use them to find which step is slow. |

## Grafana dashboard

[`dashboards/silicaproxy-overview.json`](../dashboards/silicaproxy-overview.json) is a ready-made
Grafana dashboard built on the metrics above: availability, decision and block rates, security
bypass, sync freshness, CA expiry, latencies, external dependencies, JVM and audit log.

It expects:

- a **Prometheus** data source whose uid is `prometheus` (edit the `datasource` entries of the
  JSON before importing if yours has another uid);
- SilicaProxy scraped under the job name **`silicaproxy`**, for example:
  ```yaml
  scrape_configs:
    - job_name: silicaproxy
      metrics_path: /actuator/prometheus
      static_configs:
        - targets: ["silicaproxy-host:8080"]
  ```

Import it from *Dashboards > New > Import*. The `instance` variable selects one instance or all of
them; the method latency panels can be filtered by class.
