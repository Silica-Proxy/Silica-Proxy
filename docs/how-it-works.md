# How it works

SilicaProxy evaluates security decisions in order of priority, pulling from multiple data sources. What happens when a check cannot get an answer is described in [When a check cannot answer](#when-a-check-cannot-answer).

## 1. Company policies — GitOps sync every 10 minutes (Priority 1)

Internal allow/block rules are read from a Git repository containing one YAML file per ecosystem (`npm.yaml`, `pypi.yaml`, `maven.yaml`). The scheduler pulls changes every 10 minutes and synchronises the `company_policies` table. These rules have the **highest priority** in the decision pipeline and always override external vulnerability data. How to write them: [Company policies](policies.md).

---

## 2. Public vulnerabilities — nightly batch sync + hourly incremental (Priority 2)

These are downloaded once a day (at 2:00 server time, under the ShedLock lock `VulnerabilitySyncScheduler_sync`) and stored locally in PostgreSQL, so every proxy decision is resolved from a local SQL query with no external dependency at request time.

| Source | What it covers | Format |
|---|---|---|
| **Google OSV** | CVEs for npm, PyPI, Maven | ZIP archives downloaded per ecosystem |
| **GitHub Advisory Database (GHSA)** | Curated security advisories across all ecosystems | Git clone (`github/advisory-database`) |
| **GitLab Advisory Database** | Additional npm and Maven advisories (`advisories-community`), translated to OSV ranges | Git clone |
| **OpenSSF Malicious Packages** | Known malware, typosquatting campaigns, sabotage incidents | Git clone |

All six sources (3 OSV ZIPs + 3 Git repositories) are synchronized **in parallel** on virtual threads, except the three Git fetches, which run one at a time to bound heap usage (a failed fetch is retried on its own). A failure in one source (e.g. a Git repository temporarily unreachable) does not block or delay the others. Progress is tracked per-job and visible at `/api/vulnerabilities/sync/status`.

Within a single OSV ZIP, one malformed advisory (unexpected JSON shape) does not abort the whole ~500k-entry run either: it's logged, counted in `sync_run_history.items_failed`, and skipped — the rest of the archive is still ingested, matching the per-advisory resilience of the hourly incremental sync below.

SemVer version ranges from the advisories are flattened into a concrete list of affected versions at ingestion time, enabling a fast JSONB containment check (`@>`) at query time.

### 2.1 Incremental OSV updates — hourly sync (between nightly batches)

Between nightly batch syncs, SilicaProxy fetches the `modified_id.csv` index files published by Google on the same GCS bucket. These files list every advisory modified in the last N hours, sorted newest-first. The service reads them from the top and stops as soon as it reaches an entry older than its watermark, so only the delta is downloaded. The watermark is the start of the last successful run (in `sync_run_history`) less `overlap-minutes` (default: 15): OSV may list an advisory in the CSV after a run read it, with an earlier modified time, and replaying the overlap is harmless. A failed run does not move it.

| Ecosystem | GCS index file |
|---|---|
| npm | `https://storage.googleapis.com/osv-vulnerabilities/npm/modified_id.csv` |
| PyPI | `https://storage.googleapis.com/osv-vulnerabilities/PyPI/modified_id.csv` |
| Maven | `https://storage.googleapis.com/osv-vulnerabilities/Maven/modified_id.csv` |

For each advisory ID in the delta, the service fetches the corresponding JSON file and upserts it into `public_vulnerabilities`. An advisory OSV no longer serves (HTTP 404) is skipped, not counted as a failure. A failure on a single advisory (any other HTTP error, an empty body, an unparsable JSON) is logged and recorded in `osv_incremental_failed_advisories` — the others are still processed. Each run retries the recorded advisories first, until they succeed, a nightly zip of the ecosystem started after their last failure succeeds, or they have been retried `max-retry-attempts` times (default: 24, logged as a warning and counted with outcome `ABANDONED`). Three new `sync_status` job IDs track these runs: `osv-npm-incremental`, `osv-pypi-incremental`, `osv-maven-incremental`.

The incremental sync runs **every hour** under ShedLock (`osv-incremental-sync`). On first run (no watermark), it fetches the last `initial-lookback-hours` of changes (default: 25 h) to bridge the gap until the next nightly batch.

## 3. Public registry metadata — on-demand, cached permanently

When a package version is not in any local database, SilicaProxy asks its registry for the
**publication date** (quarantine check) and the **deprecated / yanked status** (deprecation
check). How each registry is queried, how the date is cached and how failures are handled is
described in [Quarantine](quarantine.md).

## 4. External validation services — on-demand, sync or async

Any number of external HTTP services (SBOM scanners, licence checkers, proprietary scanners)
can vet a package, synchronously or through an asynchronous callback, before the live API
fallback. See [External validation services](external-validation.md).

## 5. Live security API fallback — on-demand, configurable cache (Priority 3)

If a package passes the quarantine and deprecation checks but has no result in the local vulnerability tables, SilicaProxy queries external security APIs in order.

| Source | Notes |
|---|---|
| **OSV Live** (`api.osv.dev`) | Free, broad coverage — enabled by default, tried first |
| **deps.dev** (Google Open Source Insights) | Dependency graph and licence data — tried if OSV is disabled, or hands over to it on error |

Each source can be enabled or disabled independently (see [Configuration Reference](configuration.md#configuration-reference)). The **first enabled source that answers successfully concludes the chain** — its verdict is cached in `api_cache` with configurable TTLs:
- **BLOCK verdicts** (vulnerability found): 10,080 minutes (7 days) — safe to cache longer
- **ALLOW verdicts** (no vulnerability): 1,440 minutes (24 hours) — shorter TTL for safety
- Can be independently disabled via `cache-allow-verdict: false`

**On error, the chain hands over instead of stopping:** a source that fails (HTTP error, timeout, network issue) does not conclude the chain — the next enabled source is tried instead. Only if *every* enabled source fails does the per-source [`fail-open`](#what-fail-open--fail-closed-means) policy decide the verdict (`silicaproxy.api-fallback.<source>.fail-open`, default `true`): ALLOW if every failed source is fail-open, BLOCK if at least one is fail-closed (the most restrictive result wins). This verdict is reported with `step: API_FALLBACK_ERROR` (see [API Endpoints](api.md#api-endpoints)).

A cached BLOCK keeps the reason it was issued for: the vulnerability ids reported by the API (e.g. `GHSA-…`) are stored in `api_cache.scan_details` and returned in the 403 `detail` (`Blocked by cached OSV_LIVE verdict: GHSA-cxp5-3px4-pw24`). Entries cached before this behaviour have no ids and only name the source.

This error verdict is **deliberately never cached** — caching it would keep allowing (or blocking) the package for the whole TTL window even after the failing API recovers, turning a transient outage into a security hole (fail-open) or a needless block (fail-closed) that outlives the actual incident. The next request after recovery gets a fresh, real verdict.

---

## When a check cannot answer

### What "fail-open" / "fail-closed" means

Several of the checks above depend on a remote call that can fail (a registry being
unreachable, an external validation service timing out, the OSV/deps.dev live APIs returning
an error). Each of these checks has a configurable policy for that failure case:

- **`fail-open: true`** (the default almost everywhere) — if the check can't get an answer,
  **allow** the package rather than block a build over an infrastructure hiccup.
- **`fail-open: false`** (i.e. fail-closed) — if the check can't get an answer, **block** the
  package instead, favoring security over availability.

This choice is configured independently for quarantine (`silicaproxy.quarantine.fail-open`,
[§3](quarantine.md)), each external validation
service (`...services.<name>.fail-open`, [§4](external-validation.md)),
and each live API fallback source (`silicaproxy.api-fallback.<osv|deps-dev>.fail-open`,
[§5](#5-live-security-api-fallback--on-demand-configurable-cache-priority-3)) — a hardened
environment can flip any of them to fail-closed without affecting the others.

For quarantine, `silicaproxy.quarantine.fail-open` (default `true`) decides the verdict whenever
the **publication date cannot be resolved** at all: registry unreachable, package/version
unknown to the registry (and to the origin registry for npm), and no date already cached in
`package_metadata`. Such packages skip the age check entirely, so every occurrence is counted in
`silicaproxy.quarantine.publish_date.unresolved` (tagged with the final verdict) — see
[Metrics](operations.md#metrics) for a ready-to-use alert.

Fail-open only skips the checks that need the publication date (age, deprecation): the
[external validation services](external-validation.md) still
run, each under its own `fail-open` policy, and a BLOCK from any of them wins. A service
configured `fail-open: false` that cannot vet the package during a public registry outage (for
instance because it downloads it from that registry) therefore blocks it. A service that cannot
fetch a package should answer with an error, never `BLOCKED` : a `BLOCKED` verdict is permanent.

Two options narrow that gap without turning the whole quarantine fail-closed:

- **`silicaproxy.quarantine.unknown-version-action`** — a version that every registry consulted
  answered it does **not know** (HTTP 404, version absent from the release list) is not an outage.
  `FOLLOW_FAIL_OPEN` (default) treats it like one, so `fail-open` decides; `BLOCK` always blocks
  it with `step: REGISTRY_NOT_FOUND`. A registry that could not answer (5xx, timeout, network
  error, unparseable response) still follows `fail-open`.
- **`silicaproxy.quarantine.check-vulnerabilities-on-registry-error`** — with `true` (default), a
  package let through by `fail-open` still goes through the
  [OSV/deps.dev chain](#5-live-security-api-fallback--on-demand-configurable-cache-priority-3):
  a BLOCK wins, otherwise the verdict stays `REGISTRY_ERROR` ALLOW. `false` skips the live
  vulnerability APIs for such packages.

Neither verdict is cached: the next request re-evaluates the package. The `REGISTRY_ERROR` ALLOW
in particular is **never cached**, even when every external validation service allowed the
package: caching it would skip the quarantine check for the whole TTL once the registry recovers.

#### Upstream rate limiting (HTTP 429)

A rate limit is not handled like an outage: whoever can send enough requests through the proxy
can provoke one, and following `fail-open` would then let a freshly published version skip the
quarantine — for good, since the artifacts repository in front keeps it in its cache.

- **The host is left alone.** After a 429 from a registry, OSV or deps.dev, no call is sent to that
  host until its `Retry-After` (seconds or HTTP date), or a backoff doubled on each new 429 when it
  sent none — always within `[min-backoff-seconds, max-backoff-seconds]` (5 s – 15 min by
  default). Meanwhile, relayed requests to it get a `429` with the remaining `Retry-After`, and
  Maven's second publish-date lookup (on the requested URL) is skipped when it targets the same
  host. Per instance, in memory; the first 2xx after a suspension resets the backoff.
- **The decision fails closed** with `upstream-throttle.on-throttle: FAIL_CLOSED` (default): a
  publish date that only a rate-limited registry could give (no cached date), an OSV/deps.dev check
  that only failed on 429, or a deps.dev digest lookup that did, block with `step: UPSTREAM_THROTTLED`
  — answered **`429` with `Retry-After` and `Cache-Control: no-store`** rather than 403, so the
  artifacts repository retries later instead of remembering the artifact as forbidden. This verdict
  is never cached. A cached publish date still lets the quarantine decide normally.
  `FOLLOW_FAIL_OPEN` restores the previous behaviour (each source's `fail-open` decides). Only 429
  counts: a 5xx, a timeout or a network error still follows `fail-open`.
