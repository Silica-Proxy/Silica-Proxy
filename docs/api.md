# API Endpoints

Endpoints marked `READ` or `ACTION` in the **Auth** column require `Authorization: Bearer {key}`,
using `silicaproxy.security.api-auth.key-read` or `-key-action` respectively (see
[Configuration Reference](configuration.md#full-variable-table)); a missing or wrong key returns `401`. `ACTION`
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
| `GET /actuator/health/liveness` | — | Liveness probe (JVM only) — see [Health probes](operations.md#health-probes) |
| `GET /actuator/health/readiness` | — | Readiness probe (database) — see [Health probes](operations.md#health-probes) |
| `GET /actuator/health/sync` | — | Synchronizations and MITM CA health, for monitoring only |
| `GET /actuator/health` | — | Every health component (probes + syncs + CA) |

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
| `COMPANY_POLICY` | GitOps YAML rule (`allow` or `block`) — checked first |
| `PUBLIC_VULN` | Local vulnerability database (OSV, GHSA, …) — CVSS-threshold block |
| `PUBLIC_VULN_MALWARE` | Local vulnerability database, `MAL-*` id or `source = OPENSSF` — always blocked regardless of CVSS |
| `API_CACHE` | Cached result from a previous live API call |
| `REGISTRY_ERROR` | Publication date could not be resolved (registry unreachable, or version unknown with `unknown-version-action: FOLLOW_FAIL_OPEN`) — BLOCK when fail-closed, ALLOW when [`fail-open`](data-sources.md#what-fail-open--fail-closed-means) ; never cached |
| `REGISTRY_DEPRECATION` | Package deprecated or yanked from its registry — checked before quarantine |
| `REGISTRY_QUARANTINE` | Package too recently published (anti-typosquatting) |
| `REGISTRY_NOT_FOUND` | Version unknown to every registry consulted, with `quarantine.unknown-version-action: BLOCK` — never cached |
| `UNIDENTIFIED_ARTIFACT` | npm tarball identified neither by its URL nor by a relayed packument, with `npm-packument-index.unidentified-tarball-action: BLOCK` ([details](PACKAGE_IDENTIFICATION.md#npm-tarball-identification)) |
| `EXTERNAL_VALIDATION` | External validation service (sync or async) — a real `BLOCKED` verdict, answered **403** |
| `EXTERNAL_VALIDATION_PENDING` | A blocking `fail-open: false` service is still scanning (async callback awaited, or concurrent sync call) — answered **429** with `Retry-After`, never cached ([details](data-sources.md#missing-verdict-fail-closed--429)) |
| `EXTERNAL_VALIDATION_UNAVAILABLE` | A blocking `fail-open: false` service could not give a verdict (timeout, error, unexpected verdict, unacknowledged async trigger, no callback within `pending-ttl-minutes`) — answered **429** with `Retry-After`, never cached ([details](data-sources.md#missing-verdict-fail-closed--429)) |
| `OSV_LIVE` | Google OSV live API — first fallback |
| `DEPS_DEV` | Google deps.dev live API — tried if OSV is disabled, or after OSV errors |
| `API_FALLBACK_ERROR` | Every enabled live API fallback source failed — verdict decided by [`fail-open`](data-sources.md#what-fail-open--fail-closed-means), never cached |
| `UPSTREAM_THROTTLED` | A registry, OSV or deps.dev needed for the decision is rate-limiting the proxy (429), with `upstream-throttle.on-throttle: FAIL_CLOSED` — answered **429** with `Retry-After` (not 403), never cached ([details](data-sources.md#upstream-rate-limiting-http-429)) |
