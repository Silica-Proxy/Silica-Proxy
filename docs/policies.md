# Company policies (GitOps)

One YAML file per ecosystem, at the root of the GitOps repository (`npm.yaml`, `pypi.yaml`, `maven.yaml`; `.yml` is also accepted):

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

## Rule end date (`expires`)

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

## Duplicate rules

Two rules with the same `package` and the same version pattern cannot both be stored (`1.x` and `1.*` count as the same pattern). The sync keeps the **most restrictive** one and logs an error for the other; the sync itself does not fail:

- `block` beats `allow`.
- Between two `block` rules, the one ending later wins (no end date = forever). Between two `allow` rules, the one ending sooner wins.

To make a temporary exception to a permanent `block`, use a **more specific** pattern, e.g. `allow` on `lodash` `4.17.20` with an end date next to `block` on `lodash` `*` (see [Conflict resolution](#conflict-resolution-when-multiple-rules-match)).

## Version patterns

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

## Package name patterns

`package` also accepts a `*` wildcard, to apply one rule to a whole family of packages (e.g. an entire compromised scope) instead of listing every affected name individually:

| Written in YAML | Matches |
|---|---|
| `event-stream` | exact package name only |
| `@compromised-scope/*` | any package name starting with `@compromised-scope/` |
| `*` | all packages |

Unlike version patterns, the letter `x` is **not** treated as a wildcard in package names — only `*` is. Many real package names legitimately contain an `x` (`axios`, `next`, `xml2js`...), so interpreting it as a wildcard would cause unintended matches.

## Conflict resolution when multiple rules match

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

## Severity and CVSS thresholds

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
| CRITICAL severity, CVSS 9.0 | `default-max-allowed-severity: CRITICAL` | `default-max-allowed-cvss: 9.0` | ✅ ALLOW (9.0 is not above 9.0) |

The severity level of an advisory is derived from its CVSS score through `severity_mappings` (`LOW` 0.1–3.9, `MEDIUM` 4.0–6.9, `HIGH` 7.0–8.9, `CRITICAL` 9.0–10.0). An advisory is blocked when its score is **above** `max-allowed-cvss` (the configured value itself is allowed) **or** reaches the lower bound of the first level above `max-allowed-severity` (`MEDIUM` → blocked from 7.0, `HIGH` → from 9.0, `CRITICAL` → never on severity). With the shipped defaults both criteria coincide (pypi/maven: blocked from 7.0, npm: blocked from 9.0).

The **same threshold** applies whether the advisory comes from the local tables or from the live APIs (OSV, deps.dev) queried for a package missing from them: the live answer lists every advisory of the version, and only those over the threshold block (a LOW advisory reported live no longer blocks a package the local tables would allow).

**Where the score comes from** (`AdvisorySeverityScorer`, shared by the ingestion and the live OSV check), in order:
1. a CVSS vector of `severity[]` (highest CVSS version, then highest score);
2. `database_specific.cvss.score` ;
3. the qualitative `database_specific.severity` of GHSA advisories (`LOW` / `MODERATE` / `HIGH` / `CRITICAL`), counted as the **lower bound** of its `severity_mappings` range (a `HIGH`-only advisory counts as 7.0);
4. otherwise the score is **unknown** (stored as `NULL`, never `0.0`).

**Score inherited from aliases.** Most PyPI advisories of the PYSEC database carry no severity at all, while the GHSA advisory of the same flaw does (`PYSEC-2021-142` / `GHSA-8q59-q68h-6hv4`, PyYAML, 9.8). An advisory without a score of its own takes the **highest score of the advisories it shares an id with** — its `aliases` / `upstream` ids, or a common CVE id — computed at the end of each synchronization (`inherited_cvss_score`), and the same way among the advisories of a live OSV answer. On the OSV data of October 2026, this gives a score to 94 % of the PyPI advisories that have none.

**Unknown severity.** An advisory left with no score at all, even through its aliases (about 160 PyPI advisories in October 2026), follows `severity-threshold.unknown-severity-action` : `BLOCK` (default — what cannot be assessed is blocked) or `ALLOW`. deps.dev reports advisory keys without any severity, so its advisories are always "unknown" and follow this action too.

> Rows stored before this release keep their previous score (`0.0` included) until the next full OSV synchronization rewrites them with their real (possibly unknown) score, related ids and inherited score.

**To disable severity filtering entirely**, set `severity-threshold.enabled: false` — all packages pass the threshold check regardless of CVSS or severity score, unknown ones included.

> Even when set to `false`, known malware (`id LIKE 'MAL-%'` or `source = 'OPENSSF'`) is still always blocked — this flag only disables severity/CVSS filtering for regular CVEs.

## Malware always bypasses the severity/CVSS threshold

Entries from the **OpenSSF Malicious Packages** source (typosquatting, sabotage, known malware — see [Public vulnerabilities](how-it-works.md#2-public-vulnerabilities--nightly-batch-sync--hourly-incremental-priority-2)) are not CVEs: they carry no CVSS vector or qualitative severity, since a package is malicious or it isn't — there's no "how severe" scale. Their score is therefore unknown.

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

## PyPI package names (PEP 503)

PyPI treats `PyYAML`, `pyyaml` and `py_yaml` as the same project, but file names keep the spelling of the upload (`PyYAML-6.0.2-…whl`, `typing_extensions-4.12.2-…whl`) while OSV stores the normalized name (`pyyaml`). Every PyPI name is therefore normalized as defined by [PEP 503](https://peps.python.org/pep-0503/#normalized-names) (lower case, runs of `-`, `_`, `.` replaced by a single `-`): the identified request, the ingested advisories, the GitOps rules of `pypi.yaml` (`typing_extensions` is stored as `typing-extensions`, `*` wildcards are kept), the policy evaluation and package search endpoints. The `V17` migration renames the rows already stored; when two spellings collide, the normalized one (or, for GitOps rules, the most restrictive one) is kept.

## Dependency confusion (internal namespaces)

In a dependency confusion attack, someone publishes a package named after one of your internal
packages (`@acme/utils`, `acme-auth`, `com.acme:auth`) on a public registry, with a
higher version number than the internal one. A repository manager that merges an internal
(*hosted*) repository and a public (*remote*) one into a single *virtual* repository may then
resolve the public, malicious version.

Behind a repository manager, **plain `block` rules on your internal namespaces are enough**:
internal packages are served by the hosted repositories and never go through SilicaProxy, which
only sees the traffic of the remote repositories. An internal package name reaching SilicaProxy is
therefore necessarily fetched from an external registry, and must be blocked whatever its version:

```yaml
# npm.yaml
rules:
  - package: "@acme/*"        # internal scope
    version: "*"
    action: "block"
    reason: "Internal npm scope : never fetched from a public registry"
  - package: "acme-*"         # unscoped internal packages, if any
    version: "*"
    action: "block"
    reason: "Internal npm prefix : never fetched from a public registry"

# pypi.yaml
rules:
  - package: "acme-*"         # PEP 503-normalized : also matches Acme_Auth, acme.auth...
    version: "*"
    action: "block"
    reason: "Internal PyPI prefix : never fetched from a public registry"

# maven.yaml
rules:
  - package: "com.acme:*"     # artifacts of the com.acme groupId
    version: "*"
    action: "block"
    reason: "Internal Maven groupId : never fetched from a public registry"
  - package: "com.acme.*"     # artifacts of its sub-groups (com.acme.platform:...)
    version: "*"
    action: "block"
    reason: "Internal Maven groupIds : never fetched from a public registry"
```

The client (or the virtual repository) still receives the public metadata, so it may pick the
higher public version, but downloading it fails with a `403` (`step: COMPANY_POLICY`) instead of
silently installing it.

- Keep a separator in the pattern (`@acme/*`, `acme-*`, `com.acme:*` / `com.acme.*`):
  `acme*` or `com.acme*` would also block unrelated public packages such as `acmetools` or
  `com.acmetools:lib`.
- A Maven package name is `groupId:artifactId`, hence one rule for the groupId itself and one for
  its sub-groups.
- **Do not add an `allow` rule for a package of these namespaces**: an exact package name beats a
  wildcard pattern (see [conflict resolution](#conflict-resolution-when-multiple-rules-match)), so
  `allow @acme/utils` would reopen the hole for that package.
- **This relies on internal packages never going through SilicaProxy.** If some of them are
  fetched through a remote repository (internal packages published on GitHub Packages
  `npm.pkg.github.com`, a GitLab package registry, a subsidiary's repository manager), or if
  clients use SilicaProxy directly as their HTTP(S) proxy without excluding the internal registry
  (`NO_PROXY`), these rules block those internal packages too.
- Repository managers can also exclude these namespaces natively, repository by repository
  (Artifactory *exclude patterns* on remote repositories, Nexus *routing rules*); the GitOps rules
  above apply the same protection centrally, versioned in Git.
