# Configuration Reference

Every YAML property can be overridden by an environment variable. Spring Boot's relaxed binding convention: replace dots and hyphens with `_`, uppercase everything (e.g. `silicaproxy.quarantine.fail-open` → `SILICAPROXY_QUARANTINE_FAIL_OPEN`).

## Full variable table

| Category | YAML property | Environment variable                                              | Default | Description |
|---|---|-------------------------------------------------------------------|---|---|
| **Database** | `spring.datasource.url` | `SPRING_DATASOURCE_URL`                                           | `jdbc:postgresql://localhost:5432/security_db` | PostgreSQL JDBC URL |
| | `spring.datasource.username` | `SPRING_DATASOURCE_USERNAME`                                      | `postgres` | |
| | `spring.datasource.password` | `SPRING_DATASOURCE_PASSWORD`                                      | `postgres` | |
| **Connection pool** | `spring.datasource.hikari.maximum-pool-size` | `HIKARI_MAX_POOL_SIZE`                                            | `70` | Max DB connections |
| | `spring.datasource.hikari.minimum-idle` | `HIKARI_MIN_IDLE`                                                 | `15` | Min idle connections |
| | `spring.datasource.hikari.connection-timeout` | `HIKARI_CONNECTION_TIMEOUT`                                       | `1500` | ms to wait for a connection |
| **Proxy** | `silicaproxy.proxy.port` | `SILICAPROXY_PROXY_PORT`                                          | `8080` | Public TCP entry point |
| | `silicaproxy.proxy.http-only-hosts` | `SILICAPROXY_PROXY_HTTP_ONLY_HOSTS`                               | _(empty)_ | Comma-separated, case-insensitive list of hosts that stay on plain HTTP. Every other non-local `http://` request is upgraded to `https://`, both for the upstream relay and for the registry metadata lookups (some registries, e.g. `plugins.gradle.org`, answer 403 to plain HTTP). Use it for an internal registry that has no TLS |
| | `silicaproxy.proxy.trusted-proxies` | `SILICAPROXY_PROXY_TRUSTED_PROXIES`                               | _(empty)_ | Comma-separated IPs or CIDR ranges of the HTTP reverse proxies / load balancers whose `X-Forwarded-For` gives the client address recorded in the audit log (right-most untrusted hop). Empty = `X-Forwarded-For` is ignored — see [Client identity in the audit log](operations.md#client-identity-in-the-audit-log) |
| **Registries** | `silicaproxy.registries.npm-url` | `SILICAPROXY_REGISTRIES_NPM_URL`                                  | `https://registry.npmjs.org` | npm registry base URL for metadata resolution |
| | `silicaproxy.registries.pypi-url` | `SILICAPROXY_REGISTRIES_PYPI_URL`                                 | `https://pypi.org` | PyPI registry base URL for metadata resolution |
| | `silicaproxy.registries.maven-url` | `SILICAPROXY_REGISTRIES_MAVEN_URL`                                | `https://repo1.maven.org` | Maven Central base URL for metadata resolution |
| **Quarantine** | `silicaproxy.quarantine.enabled` | `SILICAPROXY_QUARANTINE_ENABLED`                                  | `true` | Enable age-based quarantine globally |
| | `silicaproxy.quarantine.fail-open` | `SILICAPROXY_QUARANTINE_FAIL_OPEN`                                | `true` | Verdict when the publication date cannot be resolved (registry unreachable, package unknown, no cached date) : `true` = allow, `false` = block |
| | `silicaproxy.quarantine.default-min-age-days` | `SILICAPROXY_QUARANTINE_DEFAULT_MIN_AGE_DAYS`                     | `7` | Fallback threshold if not set per ecosystem |
| | `silicaproxy.quarantine.ecosystems.npm.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_NPM_ENABLED`                   | `true` | |
| | `silicaproxy.quarantine.ecosystems.npm.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_NPM_MIN_AGE_DAYS`              | `7` | |
| | `silicaproxy.quarantine.ecosystems.pypi.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_PYPI_ENABLED`                  | `true` | |
| | `silicaproxy.quarantine.ecosystems.pypi.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_PYPI_MIN_AGE_DAYS`             | `10` | |
| | `silicaproxy.quarantine.ecosystems.maven.enabled` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_MAVEN_ENABLED`                 | `false` | |
| | `silicaproxy.quarantine.ecosystems.maven.min-age-days` | `SILICAPROXY_QUARANTINE_ECOSYSTEMS_MAVEN_MIN_AGE_DAYS`            | `5` | |
| | `silicaproxy.quarantine.unknown-version-action` | `SILICAPROXY_QUARANTINE_UNKNOWN_VERSION_ACTION`                   | `FOLLOW_FAIL_OPEN` | Version unknown to every registry consulted (404) : `FOLLOW_FAIL_OPEN` = treated like an outage (`fail-open` decides), `BLOCK` = blocked (`REGISTRY_NOT_FOUND`) |
| | `silicaproxy.quarantine.check-vulnerabilities-on-registry-error` | `SILICAPROXY_QUARANTINE_CHECK_VULNERABILITIES_ON_REGISTRY_ERROR` | `true` | Still run OSV/deps.dev when `fail-open` allows a package without publish date ; a BLOCK wins, an ALLOW is never cached |
| **Deprecation** | `silicaproxy.deprecation.enabled` | `SILICAPROXY_DEPRECATION_ENABLED`                                 | `true` | Block deprecated/yanked packages |
| | `silicaproxy.deprecation.ecosystems.npm` | `SILICAPROXY_DEPRECATION_ECOSYSTEMS_NPM`                          | `true` | |
| | `silicaproxy.deprecation.ecosystems.pypi` | `SILICAPROXY_DEPRECATION_ECOSYSTEMS_PYPI`                         | `true` | |
| **CVSS threshold** | `silicaproxy.severity-threshold.enabled` | `SILICAPROXY_SEVERITY_THRESHOLD_ENABLED`                          | `true` | |
| | `silicaproxy.severity-threshold.default-max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_DEFAULT_MAX_ALLOWED_SEVERITY`     | `CRITICAL` | Severity level above which a package is blocked |
| | `silicaproxy.severity-threshold.default-max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_DEFAULT_MAX_ALLOWED_CVSS`         | `7.0` | Score above which a package is blocked |
| | `silicaproxy.severity-threshold.unknown-severity-action` | `SILICAPROXY_SEVERITY_THRESHOLD_UNKNOWN_SEVERITY_ACTION`          | `BLOCK` | `BLOCK` or `ALLOW` an advisory with no score at all, even through its aliases (see below) |
| | `silicaproxy.severity-threshold.ecosystems.npm.max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_NPM_MAX_ALLOWED_SEVERITY` | `HIGH` | |
| | `silicaproxy.severity-threshold.ecosystems.npm.max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_NPM_MAX_ALLOWED_CVSS`  | `9.0` | |
| | `silicaproxy.severity-threshold.ecosystems.maven.max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_MAVEN_MAX_ALLOWED_SEVERITY` | `MEDIUM` | |
| | `silicaproxy.severity-threshold.ecosystems.maven.max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_MAVEN_MAX_ALLOWED_CVSS` | `7.0` | |
| | `silicaproxy.severity-threshold.ecosystems.pypi.max-allowed-severity` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_PYPI_MAX_ALLOWED_SEVERITY` | `MEDIUM` | |
| | `silicaproxy.severity-threshold.ecosystems.pypi.max-allowed-cvss` | `SILICAPROXY_SEVERITY_THRESHOLD_ECOSYSTEMS_PYPI_MAX_ALLOWED_CVSS` | `7.0` | |
| **API cache** | `silicaproxy.api-cache.cache-allow-verdict` | `SILICAPROXY_API_CACHE_CACHE_ALLOW_VERDICT`                       | `true` | Cache verdicts where no vulnerability found |
| | `silicaproxy.api-cache.block-verdict-ttl-minutes` | `SILICAPROXY_API_CACHE_BLOCK_VERDICT_TTL_MINUTES`                 | `10080` | Minutes to cache when vulnerability is found (7 days) |
| | `silicaproxy.api-cache.allow-verdict-ttl-minutes` | `SILICAPROXY_API_CACHE_ALLOW_VERDICT_TTL_MINUTES`                 | `1440` | Minutes to cache when no vulnerability found (24 hours) |
| **GitOps** | `silicaproxy.gitops.enabled` | `SILICAPROXY_GITOPS_ENABLED`                                      | `true` | |
| | `silicaproxy.gitops.repository-url` | `SILICAPROXY_GITOPS_REPOSITORY_URL`                               | `http://localhost:3000/devops/policies.git` | URL of the policy Git repository |
| | `silicaproxy.gitops.directory-path` | `SILICAPROXY_GITOPS_DIRECTORY_PATH`                               | `policies/` | Subfolder inside the repo |
| | `silicaproxy.gitops.clone-token` | `SILICAPROXY_GITOPS_CLONE_TOKEN`                                  | _(empty)_ | OAuth token or PAT for private repos |
| | `silicaproxy.gitops.sync-interval-minutes` | `SILICAPROXY_GITOPS_SYNC_INTERVAL_MINUTES`                        | `10` | |
| **SSL MITM** | `silicaproxy.ssl-mitm.ca-keystore-path` | `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH`                           | `./certs/ca.p12` | PKCS12 path — empty = ephemeral CA |
| | `silicaproxy.ssl-mitm.ca-keystore-password` | `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD`                       | _(empty)_ | Keystore password for encryption |
| | `silicaproxy.ssl-mitm.ca-cert-export-path` | `SILICAPROXY_SSL_MITM_CA_CERT_EXPORT_PATH`                        | `/tmp/silicaproxy-ca.crt` | Public CA certificate export path (PEM) |
| | `silicaproxy.ssl-mitm.context-cache-max-entries` | `SILICAPROXY_SSL_MITM_CONTEXT_CACHE_MAX_ENTRIES`                  | `2000` | Hard cap on the per-host SSLContext cache, on top of its 24h inactivity TTL — bounds the CPU/memory cost of CONNECT requests to many distinct hostnames |
| **npm tarball index** | `silicaproxy.npm-packument-index.enabled` | `SILICAPROXY_NPM_PACKUMENT_INDEX_ENABLED`                         | `true` | Learn tarball URLs from relayed packuments ([npm tarball identification](PACKAGE_IDENTIFICATION.md#npm-tarball-identification)) |
| | `silicaproxy.npm-packument-index.max-entries` | `SILICAPROXY_NPM_PACKUMENT_INDEX_MAX_ENTRIES`                     | `200000` | Hard cap on in-memory entries |
| | `silicaproxy.npm-packument-index.ttl-minutes` | `SILICAPROXY_NPM_PACKUMENT_INDEX_TTL_MINUTES`                     | `60` | Lifetime of an entry, in memory and in `npm_tarball_index` |
| | `silicaproxy.npm-packument-index.max-body-bytes` | `SILICAPROXY_NPM_PACKUMENT_INDEX_MAX_BODY_BYTES`                  | `33554432` | Larger packuments are relayed without being indexed |
| | `silicaproxy.npm-packument-index.max-decoded-bytes` | `SILICAPROXY_NPM_PACKUMENT_INDEX_MAX_DECODED_BYTES`               | `134217728` | Same cap on the decompressed body (gzip bomb guard) |
| | `silicaproxy.npm-packument-index.max-concurrent-indexing` | `SILICAPROXY_NPM_PACKUMENT_INDEX_MAX_CONCURRENT_INDEXING`         | `16` | Packuments indexed at once ; beyond, relayed without indexing |
| | `silicaproxy.npm-packument-index.unidentified-tarball-action` | `SILICAPROXY_NPM_PACKUMENT_INDEX_UNIDENTIFIED_TARBALL_ACTION`     | `ALLOW` | npm `.tgz` identified neither by URL nor by index : `ALLOW` = relayed unchecked, `BLOCK` = 403 (`UNIDENTIFIED_ARTIFACT`) |
| **Upstream rate limiting** | `silicaproxy.upstream-throttle.enabled` | `SILICAPROXY_UPSTREAM_THROTTLE_ENABLED` | `true` | Suspend calls to a host that answered 429 ([details](data-sources.md#upstream-rate-limiting-http-429)). `false` = a 429 is handled like any other upstream failure |
| | `silicaproxy.upstream-throttle.on-throttle` | `SILICAPROXY_UPSTREAM_THROTTLE_ON_THROTTLE` | `FAIL_CLOSED` | Decision that needed a rate-limited host : `FAIL_CLOSED` = blocked (`UPSTREAM_THROTTLED`, answered 429 + `Retry-After`, never cached), `FOLLOW_FAIL_OPEN` = treated like an outage |
| | `silicaproxy.upstream-throttle.default-backoff-seconds` | `SILICAPROXY_UPSTREAM_THROTTLE_DEFAULT_BACKOFF_SECONDS` | `30` | Suspension when the host sent no usable `Retry-After`, doubled on each consecutive 429 |
| | `silicaproxy.upstream-throttle.min-backoff-seconds` | `SILICAPROXY_UPSTREAM_THROTTLE_MIN_BACKOFF_SECONDS` | `5` | Lower bound of a suspension |
| | `silicaproxy.upstream-throttle.max-backoff-seconds` | `SILICAPROXY_UPSTREAM_THROTTLE_MAX_BACKOFF_SECONDS` | `900` | Upper bound of a suspension, `Retry-After` included |
| **Response identification** | `silicaproxy.response-identification.enabled` | `SILICAPROXY_RESPONSE_IDENTIFICATION_ENABLED`                     | `true` | Identify unidentified downloads from the digest the upstream announces, via `file_digest_index` then deps.dev ([details](PACKAGE_IDENTIFICATION.md#identification-from-the-upstream-response)). `false` turns the feature off entirely |
| **Corporate proxy** | `silicaproxy.corporate-proxy.enabled` | `SILICAPROXY_CORPORATE_PROXY_ENABLED`                             | `false` | Route outbound traffic through a corporate proxy |
| | `silicaproxy.corporate-proxy.host` | `SILICAPROXY_CORPORATE_PROXY_HOST`                                | — | |
| | `silicaproxy.corporate-proxy.port` | `SILICAPROXY_CORPORATE_PROXY_PORT`                                | — | |
| | `silicaproxy.corporate-proxy.non-proxy-hosts` | `SILICAPROXY_CORPORATE_PROXY_NON_PROXY_HOSTS`                     | `localhost\|127.0.0.1` | Pipe-separated bypass list |
| | `silicaproxy.corporate-proxy.scope.registries` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_REGISTRIES`                    | `true` | Route registry traffic through proxy |
| | `silicaproxy.corporate-proxy.scope.security-apis` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_SECURITY_APIS`                 | `true` | Route security API traffic through proxy |
| | `silicaproxy.corporate-proxy.scope.external-git-repositories` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_EXTERNAL_GIT_REPOSITORIES`     | `true` | Route vulnerability DB git clones through proxy |
| | `silicaproxy.corporate-proxy.scope.internal-git-repository` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_INTERNAL_GIT_REPOSITORY`       | `false` | Route GitOps repo through proxy |
| **External validation** | `silicaproxy.external-validation.callback-base-url` | `SILICAPROXY_EXTERNAL_VALIDATION_CALLBACK_BASE_URL`               | _(empty)_ | Base URL of this proxy instance — **required if any service uses `mode: async`**, and checked at startup: the proxy refuses to start rather than send a broken relative callback URL |
| | `silicaproxy.external-validation.trigger-async-on-sync-block` | `SILICAPROXY_EXTERNAL_VALIDATION_TRIGGER_ASYNC_ON_SYNC_BLOCK`     | `false` | If true, async services are triggered even when a sync service already returned `BLOCKED` (a sync service without a verdict never prevents the trigger) |
| | `silicaproxy.external-validation.retry-after-seconds` | `SILICAPROXY_EXTERNAL_VALIDATION_RETRY_AFTER_SECONDS` | `30` | `Retry-After` of the 429 answered while a fail-closed service has no verdict yet. See [Missing verdict](data-sources.md#missing-verdict-fail-closed--429) |
| | `silicaproxy.external-validation.services.<name>.enabled` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_ENABLED`          | `false` | Enable this external validation service |
| | `silicaproxy.external-validation.services.<name>.url` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_URL`              | — | HTTP endpoint to POST validation requests to |
| | `silicaproxy.external-validation.services.<name>.api-key` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_APIKEY`           | _(empty)_ | Sent as `Authorization` header on outbound calls; for async services, also required back as `Authorization: Bearer {api-key}` on the callback if set (optional otherwise) |
| | `silicaproxy.external-validation.services.<name>.mode` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_MODE`             | — | `sync` (wait for response) or `async` (fire-and-forget + callback) |
| | `silicaproxy.external-validation.services.<name>.timeout-seconds` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_TIMEOUTSECONDS`                                                               | `1` | Max wait time in sync mode — on timeout, `fail-open` policy applies |
| | `silicaproxy.external-validation.services.<name>.fail-open` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_FAILOPEN`                                                                | `true` | `true` = allow on error/timeout/pending; `false` = block temporarily (429 + `Retry-After`, see [Missing verdict](data-sources.md#missing-verdict-fail-closed--429)) — ignored when `blocking: false` |
| | `silicaproxy.external-validation.services.<name>.blocking` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_BLOCKING`                                                                | `true` | `false` = verdict stored for audit but never blocks a package |
| | `silicaproxy.external-validation.services.<name>.cache-ttl-minutes` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_CACHETTLMINUTES`                                                               | `0` ⚠️ | How long to cache an ALLOW verdict — **no implicit default, must be set explicitly** |
| | `silicaproxy.external-validation.services.<name>.pending-ttl-minutes` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_PENDINGTTLMINUTES`                                                                | `30` | Async only — how long to keep a PENDING entry before marking it TIMEOUT (falls back to 30 if unset or `0`) |
| | `silicaproxy.external-validation.services.<name>.head-check` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_HEADCHECK` | `false` | `true` = HEAD on the requested URL before calling this service; a 404 skips the service for that request. See [Upstream HEAD check](data-sources.md#upstream-head-check-head-check) |
| | `silicaproxy.external-validation.services.<name>.head-check-timeout-seconds` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_HEADCHECKTIMEOUTSECONDS` | `5` | Timeout of the HEAD check. On timeout or error the service is called as usual |
| | `silicaproxy.external-validation.services.<name>.head-check-cache-ttl-minutes` | `SILICAPROXY_EXTERNALVALIDATION_SERVICES_<NAME>_HEADCHECKCACHETTLMINUTES` | `10` | How long the HEAD outcome (found / not found) is cached in PostgreSQL (`upstream_head_cache`), shared across instances |
| | `silicaproxy.http-client.external-validation-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_EXTERNAL_VALIDATION_READ_TIMEOUT_SECONDS` | `1` | HTTP read timeout for the async trigger call (acknowledgment only) — sync calls wait for `services.<name>.timeout-seconds` instead |
| | `silicaproxy.corporate-proxy.scope.external-validation` | `SILICAPROXY_CORPORATE_PROXY_SCOPE_EXTERNAL_VALIDATION`           | `false` | Route external validation traffic through the corporate proxy |
| **API call log** | `silicaproxy.api-call-log.enabled` | `SILICAPROXY_API_CALL_LOG_ENABLED`                                | `false` | Audit every live OSV/deps.dev call in `api_call_log` — **disabled by default, see warning below** |
| | `silicaproxy.api-call-log.flush-interval-seconds` | `SILICAPROXY_API_CALL_LOG_FLUSH_INTERVAL_SECONDS`                 | `30` | Batch flush interval (seconds) |
| | `silicaproxy.api-call-log.buffer-capacity` | `SILICAPROXY_API_CALL_LOG_BUFFER_CAPACITY`                        | `5000` | In-memory buffer size before entries are dropped |
| **OSV incremental** | `silicaproxy.osv-incremental.enabled` | `SILICAPROXY_OSV_INCREMENTAL_ENABLED`                             | `true` | Enable hourly incremental OSV sync |
| | `silicaproxy.osv-incremental.gcs-base-url` | `SILICAPROXY_OSV_INCREMENTAL_GCS_BASE_URL`                        | `https://storage.googleapis.com/osv-vulnerabilities` | GCS base URL for `modified_id.csv` files |
| | `silicaproxy.osv-incremental.initial-lookback-hours` | `SILICAPROXY_OSV_INCREMENTAL_INITIAL_LOOKBACK_HOURS`              | `25` | Window fetched on first run (before any watermark) |
| | `silicaproxy.osv-incremental.overlap-minutes` | `SILICAPROXY_OSV_INCREMENTAL_OVERLAP_MINUTES`                     | `15` | Minutes read back before the start of the last successful run |
| | `silicaproxy.osv-incremental.max-retry-attempts` | `SILICAPROXY_OSV_INCREMENTAL_MAX_RETRY_ATTEMPTS`                  | `24` | Hourly retries of a failed advisory before leaving it to the nightly zip |
| **Health** | `silicaproxy.health.osv-max-staleness-hours` | `SILICAPROXY_HEALTH_OSV_MAX_STALENESS_HOURS`                      | `48` | The `vulnerabilitySync` health component turns `DOWN` only when no OSV source (nightly zip or hourly incremental) has succeeded for this many hours; a single failed or late job is `DEGRADED`. Never used by the liveness/readiness probes — see [Health probes](operations.md#health-probes) |
| **Fallback APIs** | `silicaproxy.api-fallback.osv.enabled` | `SILICAPROXY_API_FALLBACK_OSV_ENABLED`                            | `true` | Enable Google OSV Live API (free) |
| | `silicaproxy.api-fallback.osv.url` | —                                                                 | `https://api.osv.dev/v1/query` | OSV API endpoint |
| | `silicaproxy.api-fallback.osv.fail-open` | `SILICAPROXY_API_FALLBACK_OSV_FAIL_OPEN`                          | `true` | Verdict when OSV fails **and** no later source in the chain concludes either (see [Live security API fallback](data-sources.md#5-live-security-api-fallback--on-demand-configurable-cache-priority-3)) |
| | `silicaproxy.api-fallback.deps-dev.enabled` | `SILICAPROXY_API_FALLBACK_DEPS_DEV_ENABLED`                       | `true` | Enable Google deps.dev API (free) |
| | `silicaproxy.api-fallback.deps-dev.url` | —                                                                 | `https://api.deps.dev/v3/` | deps.dev API endpoint |
| | `silicaproxy.api-fallback.deps-dev.fail-open` | `SILICAPROXY_API_FALLBACK_DEPS_DEV_FAIL_OPEN`                     | `true` | Verdict when deps.dev fails **and** no later source in the chain concludes either |
| **HTTP timeouts** | `silicaproxy.http-client.connect-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_CONNECT_TIMEOUT_SECONDS`                 | `5` | |
| | `silicaproxy.http-client.registries-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_REGISTRIES_READ_TIMEOUT_SECONDS`         | `60` | For binary downloads |
| | `silicaproxy.http-client.security-apis-read-timeout-seconds` | `SILICAPROXY_HTTP_CLIENT_SECURITY_APIS_READ_TIMEOUT_SECONDS`      | `10` | For JSON security API calls |
| **SSRF protection** | `silicaproxy.security.ssrf-protection.enabled` | `SILICAPROXY_SECURITY_SSRF_PROTECTION_ENABLED`                    | `true` | Block outbound calls to loopback/private IPs |
| **API key auth** | `silicaproxy.security.api-auth.enabled` | `SILICAPROXY_SECURITY_API_AUTH_ENABLED`                           | `true` | Require a Bearer API key on internal admin/API endpoints (see [API Endpoints](api.md#api-endpoints)) — set `false` only for local dev/tests |
| | `silicaproxy.security.api-auth.key-read` | `SILICAPROXY_API_KEY_READ`                                        | _(empty)_ | Bearer key for read-only endpoints (consultation, no side effect) |
| | `silicaproxy.security.api-auth.key-action` | `SILICAPROXY_API_KEY_ACTION`                                      | _(empty)_ | Bearer key for action endpoints (triggers a side effect, e.g. forced sync) — also grants access to `READ` endpoints |

> **Warning — API call log performance impact:** enabling `silicaproxy.api-call-log.enabled` generates one database row per package that reaches the live API fallback (OSV Live / deps.dev). In a busy CI/CD environment where many unknown packages are requested simultaneously, this can produce hundreds of writes per minute. Calls are buffered in memory and flushed in batches (configurable via `flush-interval-seconds`), so the write never blocks the security decision path. However, the underlying PostgreSQL table (`api_call_log`) will grow at the rate of live API calls, and partition maintenance (creating monthly partitions) must be planned. Only enable in production if you have a monitoring setup to track table growth.

> **Warning — `cache-ttl-minutes` has no implicit default:** if left unset for an external validation service, it binds to `0`, which means every cached ALLOW verdict is treated as already expired — the sync service is re-called (or, for an async ALLOWED callback, the next request re-triggers async validation) on **every single request** instead of being cached. Always set it explicitly for any service you configure. The startup log (see [Observability](operations.md#observability)) prints the effective value of every service, so a missing TTL is immediately visible.

---

## GitOps policy files

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

  - package: "minimist"
    version: "1.2.5"
    action: "allow"
    reason: "Temporary exception while migrating to 1.2.8 — ticket SEC-123"
    expires: "2026-12-31"
```

### Rule end date (`expires`)

`expires` is optional. Without it, a rule never expires.

```yaml
  - package: "minimist"
    version: "1.2.5"
    action: "allow"
    reason: "Temporary exception while migrating to 1.2.8"
    expires: "2026-12-31"        # valid through the end of 31 Dec, UTC
```

| `expires` | Rule applies until (exclusive) |
|---|---|
| `"2026-12-31"` | `2027-01-01T00:00:00Z` (whole day, UTC) |
| `"2026-12-31T18:00:00+02:00"` | `2026-12-31T16:00:00Z` |
| `"2026-12-31T18:00:00"` | `2026-12-31T18:00:00Z` (no offset = UTC) |

- Checked on every request: a rule stops at its exact end date, without waiting for the next sync. Adding or changing a date takes effect at the next sync.
- An expired rule is ignored; the decision falls through to the other sources.
- Expired rules are not stored. A warning is logged for rules ending within 7 days.
- **An unreadable date fails closed:** an `allow` with a bad `expires` is rejected, so a typo never makes an exception permanent. A `block` with a bad `expires` is kept without end date. Both cases are logged as errors.

### Duplicate rules

Two rules with the same `package` and the same version pattern cannot both be stored (`1.x` and `1.*` count as the same pattern). The sync keeps the **most restrictive** one and logs an error for the other; the sync itself does not fail:

- `block` beats `allow`.
- Between two `block` rules, the one ending later wins (no end date = forever). Between two `allow` rules, the one ending sooner wins.

To make a temporary exception to a permanent `block`, use a **more specific** pattern, e.g. `allow` on `lodash` `4.17.20` with an end date next to `block` on `lodash` `*` (see [Conflict resolution](#conflict-resolution-when-multiple-rules-match)).

### Version patterns

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

### Package name patterns

`package` also accepts a `*` wildcard, to apply one rule to a whole family of packages (e.g. an entire compromised scope) instead of listing every affected name individually:

| Written in YAML | Matches |
|---|---|
| `event-stream` | exact package name only |
| `@compromised-scope/*` | any package name starting with `@compromised-scope/` |
| `*` | all packages |

Unlike version patterns, the letter `x` is **not** treated as a wildcard in package names — only `*` is. Many real package names legitimately contain an `x` (`axios`, `next`, `xml2js`...), so interpreting it as a wildcard would cause unintended matches.

### Conflict resolution when multiple rules match

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

### Severity and CVSS thresholds

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
| HIGH severity, CVSS 7.5 | `default-max-allowed-severity: MEDIUM` | `default-max-allowed-cvss: 9.0` | 🚫 BLOCK (severity > MEDIUM) |
| CRITICAL severity, CVSS 8.5 | `default-max-allowed-severity: CRITICAL` | `default-max-allowed-cvss: 9.0` | ✅ ALLOW |

The severity level of an advisory is derived from its CVSS score through `severity_mappings` (`LOW` 0.1–3.9, `MEDIUM` 4.0–6.9, `HIGH` 7.0–8.9, `CRITICAL` 9.0–10.0). An advisory is blocked when its score is **above** `max-allowed-cvss` (the configured value itself is allowed) **or** reaches the lower bound of the first level above `max-allowed-severity` (`MEDIUM` → blocked from 7.0, `HIGH` → from 9.0, `CRITICAL` → never on severity). With the shipped defaults both criteria coincide (pypi/maven : blocked from 7.0, npm : blocked from 9.0).

The **same threshold** applies whether the advisory comes from the local tables or from the live APIs (OSV, deps.dev) queried for a package missing from them : the live answer lists every advisory of the version, and only those over the threshold block (a LOW advisory reported live no longer blocks a package the local tables would allow).

**Where the score comes from** (`AdvisorySeverityScorer`, shared by the ingestion and the live OSV check), in order :
1. a CVSS vector of `severity[]` (highest CVSS version, then highest score) ;
2. `database_specific.cvss.score` ;
3. the qualitative `database_specific.severity` of GHSA advisories (`LOW` / `MODERATE` / `HIGH` / `CRITICAL`), counted as the **lower bound** of its `severity_mappings` range (a `HIGH`-only advisory counts as 7.0) ;
4. otherwise the score is **unknown** (stored as `NULL`, never `0.0`).

**Score inherited from aliases.** Most PyPI advisories of the PYSEC database carry no severity at all, while the GHSA advisory of the same flaw does (`PYSEC-2021-142` / `GHSA-8q59-q68h-6hv4`, PyYAML, 9.8). An advisory without a score of its own takes the **highest score of the advisories it shares an id with** — its `aliases` / `upstream` ids, or a common CVE id — computed at the end of each synchronization (`inherited_cvss_score`), and the same way among the advisories of a live OSV answer. On the OSV data of October 2026, this gives a score to 94 % of the PyPI advisories that have none.

**Unknown severity.** An advisory left with no score at all, even through its aliases (about 160 PyPI advisories in October 2026), follows `severity-threshold.unknown-severity-action` : `BLOCK` (default — what cannot be assessed is blocked) or `ALLOW`. deps.dev reports advisory keys without any severity, so its advisories are always "unknown" and follow this action too.

> Rows stored before this release keep their previous score (`0.0` included) until the next full OSV synchronization rewrites them with their real (possibly unknown) score, related ids and inherited score.

**To disable severity filtering entirely**, set `severity-threshold.enabled: false` — all packages pass the threshold check regardless of CVSS or severity score, unknown ones included.

> Even when set to `false`, known malware (`id LIKE 'MAL-%'` or `source = 'OPENSSF'`) is still always blocked — this flag only disables severity/CVSS filtering for regular CVEs.

### Malware always bypasses the severity/CVSS threshold

Entries from the **OpenSSF Malicious Packages** source (typosquatting, sabotage, known malware — see [Public vulnerabilities](data-sources.md#2-public-vulnerabilities--nightly-batch-sync--hourly-incremental-priority-2)) are not CVEs: they carry no CVSS vector or qualitative severity, since a package is malicious or it isn't — there's no "how severe" scale. Their score is therefore unknown.

If the standard threshold logic applied as-is, they would follow `unknown-severity-action` (or `severity-threshold.enabled: false`) and could let known-malicious packages through. To prevent this, `DecisionDao` adds an unconditional `OR` to the `public_vulnerabilities` lookup that ignores the configured thresholds entirely for these rows:

```sql
AND (id LIKE 'MAL-%' OR source = 'OPENSSF'
     OR COALESCE(cvss_score, inherited_cvss_score) > :maxAllowedCvss
     OR COALESCE(cvss_score, inherited_cvss_score) >= :severityFloor
     OR (:blockUnknown AND cvss_score IS NULL AND inherited_cvss_score IS NULL))
```

A row matches this bypass if its advisory `id` starts with `MAL-` (the OSV malware ID convention) **or** its `source` column is `OPENSSF`. Either one is always `BLOCK`, regardless of `severity-threshold.enabled` or any configured CVSS/severity value. A `MAL-` advisory reported by the live OSV API is always blocked as well.

| Entry type | Severity/CVSS threshold applies? |
|---|---|
| CVE (OSV, GHSA, GitLab) | Yes — own or inherited score against `max-allowed-cvss` and `max-allowed-severity` |
| Advisory with no score anywhere | `unknown-severity-action` (`BLOCK` by default) |
| Malware (`MAL-*` id or `source = OPENSSF`) | No — always `BLOCK` |

### PyPI package names (PEP 503)

PyPI treats `PyYAML`, `pyyaml` and `py_yaml` as the same project, but file names keep the spelling of the upload (`PyYAML-6.0.2-…whl`, `typing_extensions-4.12.2-…whl`) while OSV stores the normalized name (`pyyaml`). Every PyPI name is therefore normalized as defined by [PEP 503](https://peps.python.org/pep-0503/#normalized-names) (lower case, runs of `-`, `_`, `.` replaced by a single `-`) : the identified request, the ingested advisories, the GitOps rules of `pypi.yaml` (`typing_extensions` is stored as `typing-extensions`, `*` wildcards are kept), the policy evaluation and package search endpoints. The `V17` migration renames the rows already stored ; when two spellings collide, the normalized one (or, for GitOps rules, the most restrictive one) is kept.

### Dependency confusion (internal namespaces)

In a dependency confusion attack, someone publishes a package named after one of your internal
packages (`@moncorp/utils`, `moncorp-auth`, `com.moncorp:auth`) on a public registry, with a
higher version number than the internal one. A repository manager that merges an internal
(*hosted*) repository and a public (*remote*) one into a single *virtual* repository may then
resolve the public, malicious version.

Behind a repository manager, **plain `block` rules on your internal namespaces are enough** :
internal packages are served by the hosted repositories and never go through SilicaProxy, which
only sees the traffic of the remote repositories. An internal package name reaching SilicaProxy is
therefore necessarily fetched from an external registry, and must be blocked whatever its version :

```yaml
# npm.yaml
rules:
  - package: "@moncorp/*"        # internal scope
    version: "*"
    action: "block"
    reason: "Internal npm scope : never fetched from a public registry"
  - package: "moncorp-*"         # unscoped internal packages, if any
    version: "*"
    action: "block"
    reason: "Internal npm prefix : never fetched from a public registry"

# pypi.yaml
rules:
  - package: "moncorp-*"         # PEP 503-normalized : also matches MonCorp_Auth, moncorp.auth...
    version: "*"
    action: "block"
    reason: "Internal PyPI prefix : never fetched from a public registry"

# maven.yaml
rules:
  - package: "com.moncorp:*"     # artifacts of the com.moncorp groupId
    version: "*"
    action: "block"
    reason: "Internal Maven groupId : never fetched from a public registry"
  - package: "com.moncorp.*"     # artifacts of its sub-groups (com.moncorp.platform:...)
    version: "*"
    action: "block"
    reason: "Internal Maven groupIds : never fetched from a public registry"
```

The client (or the virtual repository) still receives the public metadata, so it may pick the
higher public version, but downloading it fails with a `403` (`step: COMPANY_POLICY`) instead of
silently installing it.

- Keep a separator in the pattern (`@moncorp/*`, `moncorp-*`, `com.moncorp:*` / `com.moncorp.*`) :
  `moncorp*` or `com.moncorp*` would also block unrelated public packages such as `moncorpus` or
  `com.moncorpus:lib`.
- A Maven package name is `groupId:artifactId`, hence one rule for the groupId itself and one for
  its sub-groups.
- **Do not add an `allow` rule for a package of these namespaces** : an exact package name beats a
  wildcard pattern (see [conflict resolution](#conflict-resolution-when-multiple-rules-match)), so
  `allow @moncorp/utils` would reopen the hole for that package.
- **This relies on internal packages never going through SilicaProxy.** If some of them are
  fetched through a remote repository (internal packages published on GitHub Packages
  `npm.pkg.github.com`, a GitLab package registry, a subsidiary's repository manager), or if
  clients use SilicaProxy directly as their HTTP(S) proxy without excluding the internal registry
  (`NO_PROXY`), these rules block those internal packages too.
- Repository managers can also exclude these namespaces natively, repository by repository
  (Artifactory *exclude patterns* on remote repositories, Nexus *routing rules*) ; the GitOps rules
  above apply the same protection centrally, versioned in Git.
