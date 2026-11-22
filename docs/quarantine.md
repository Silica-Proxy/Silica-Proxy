# Quarantine and deprecation

The **quarantine** blocks package versions published less than N days ago. Most malicious
releases (typosquatting, hijacked maintainer accounts, compromised CI) are detected and pulled from
the registry within days, so making builds wait a few days removes most of the window an attacker
relies on, without any external intelligence. The **deprecation check** blocks versions that their
registry flags as deprecated (npm) or yanked (PyPI).

Both checks run only for a package version that no local source has decided on yet (company
policy, public vulnerability database, `api_cache`) — see [How it works](how-it-works.md).

## Configuration

```yaml
silicaproxy:
  quarantine:
    enabled: true
    default-min-age-days: 7    # used for an ecosystem not listed below
    fail-open: true            # verdict when no publication date can be resolved
    ecosystems:
      npm:
        enabled: true
        min-age-days: 7
      pypi:
        enabled: true
        min-age-days: 10
      maven:
        enabled: false         # disabled by default
        min-age-days: 5
  deprecation:
    enabled: true
```

Every property, with its environment variable, is listed in the
[Configuration reference](configuration.md#full-variable-table).

## Decision order

```
publication date resolved?
  no  → fail-open / fail-closed, see "When the date cannot be resolved"
  yes → deprecated or yanked?        → BLOCK  REGISTRY_DEPRECATION  (cached permanently)
        published < min-age-days ago? → BLOCK  REGISTRY_QUARANTINE   (never cached)
        otherwise                     → external validation services, then OSV / deps.dev
```

A quarantine or deprecation block ends the evaluation: the external validation services and the
live vulnerability APIs are not called.

## How the age is computed

A version is quarantined while `now < published_at + min-age-days × 24 h`. The comparison uses
exact instants (UTC), not calendar days. The age reported in the block message is the number of
full 24-hour periods since publication:

| Published | Request | Age in the message | `min-age-days: 7` |
|---|---|---|---|
| 2026-11-20 23:00 UTC | 2026-11-20 23:59 UTC | 0 days | blocked |
| 2026-11-14 01:00 UTC | 2026-11-21 00:00 UTC | 6 days (6 d 23 h) | blocked |
| 2026-11-14 10:00 UTC | 2026-11-21 10:00 UTC | 7 days | allowed |

The block is answered with HTTP `403` and `step: REGISTRY_QUARANTINE`, for example:

```
Package requests version 2.30.0 was published 5 days ago (required threshold: 10 days).
Temporarily blocked by anti-typosquatting quarantine.
```

The quarantine verdict is never cached: the same version is allowed as soon as it ages out.

## Publication date and deprecation status


When a package version is not in any local database, SilicaProxy queries the registry to retrieve:
- **Publication date** — used for the quarantine check (anti-typosquatting)
- **Deprecation / yanked status** — used for the deprecation check (npm and PyPI only)

| Ecosystem | Default registry | Publication date | Deprecation / yanked | YAML / Env var |
|---|---|---|---|---|
| **npm** | `registry.npmjs.org` | ✓ | ✓ (`deprecated` field) | `silicaproxy.registries.npm-url` / `SILICAPROXY_REGISTRIES_NPM_URL` |
| **PyPI** | `pypi.org` | ✓ | ✓ (`yanked` field) | `silicaproxy.registries.pypi-url` / `SILICAPROXY_REGISTRIES_PYPI_URL` |
| **Maven** | `repo1.maven.org` | ✓ (`Last-Modified` header) | — not supported | `silicaproxy.registries.maven-url` / `SILICAPROXY_REGISTRIES_MAVEN_URL` |

How the publication date is resolved:

- **PyPI** — a release can receive new files (e.g. wheels for a new Python version) long after it
  was first published, so the date used is the upload time of the **file actually downloaded**
  (matched by filename against the release's files). If it can't be matched, the **most recent**
  upload of the release is used — never the first file's, which would let a freshly added file
  inherit the release's old age.
- **npm** — the configured public registry is **always asked first**. The packument relayed to the
  client, and the registry it came from (npm.jsr.io, a private Verdaccio/Artifactory…), are only
  used when the public registry answers that it does **not know** the package/version (404, or no
  `time` entry for it) — never when it merely fails to answer (5xx, timeout), so a registry outage
  can't hand the quarantine date over to a less trusted source.
- **Maven** — the `Last-Modified` header of the version directory on Maven Central
  (`HEAD /maven2/{group}/{artifact}/{version}/`). If Central does not answer with a date (404,
  artifact not mirrored there, or outage), the URL the client actually requested is `HEAD`ed
  instead and its `Last-Modified` is used.
- **All ecosystems** — every lookup tells a registry that does **not know** the package/version
  (`NOT_FOUND` : HTTP 404, version absent) apart from one that **could not answer**
  (`UNAVAILABLE` : 5xx, timeout, network error, unexpected response). Either way, a date already
  cached in `package_metadata` is used first (for PyPI only while it is still quarantined, see
  below); otherwise the
  [`quarantine.fail-open`](how-it-works.md#what-fail-open--fail-closed-means) policy decides, except that a
  `NOT_FOUND` is blocked outright when `quarantine.unknown-version-action` is `BLOCK`.

The publication date is **stored permanently** in the `package_metadata` table, one row per version. A deprecation verdict is also cached permanently. Only the quarantine verdict is never cached, so it is naturally re-evaluated at each request until the package ages out.

The registry is still queried for a version already seen, because the deprecated / yanked status is never stored and must stay fresh — except when that status can't change the verdict: the cached date says the version is still quarantined (blocked either way), or deprecation filtering is off for the ecosystem (Maven). PyPI dates each **file** of a release, and the cached date is that of whichever file was resolved first: a still-quarantined one means the release holds a fresh file, so the request is blocked without a lookup (an older file of that release may then be blocked until the fresh one ages out); any other cached date proves nothing for the requested file, which is looked up. For the same reason, no `ALLOW` is written to `api_cache` while any file of a PyPI release is still quarantined.

## Package identification

Registry metadata, like every other check, is only looked up once the request's ecosystem, package
name and version are identified — otherwise the request is relayed **without any security check**.
How each ecosystem is identified (npm tarballs, Maven artifacts, PyPI files, client header hints,
identification from the upstream response digest) and the known limits are described in
[Package identification](package-identification.md).

## When the date cannot be resolved

No registry gave a date and none is cached in `package_metadata`: the age check is skipped and
`silicaproxy.quarantine.fail-open` decides (`true`, the default, allows; `false` blocks), with
`step: REGISTRY_ERROR`. `quarantine.unknown-version-action: BLOCK` blocks a version that every
registry consulted answered it does not know (`step: REGISTRY_NOT_FOUND`). A registry that is
rate-limiting the proxy (HTTP 429) is handled separately and, by default, fails closed
(`step: UPSTREAM_THROTTLED`, answered `429`).

The full rules, including what still runs on a fail-open verdict, are in
[What "fail-open" / "fail-closed" means](how-it-works.md#what-fail-open--fail-closed-means) and
[Upstream rate limiting](how-it-works.md#upstream-rate-limiting-http-429).

## Monitoring

- `silicaproxy.quarantine.publish_date.lookups` — where each publication date came from
  (`PUBLIC_REGISTRY`, `ORIGIN_REGISTRY`, `LOCAL_CACHE`, `LOCAL_CACHE_NO_LOOKUP`, `UNRESOLVED`).
- `silicaproxy.quarantine.publish_date.unresolved` — packages that skipped the age check, tagged
  with the verdict applied. Alert on it when `fail-open` is `true`.

See [Metrics](operations.md#metrics). When the date cannot be resolved, the proxy also logs
`WARN Unable to retrieve registry metadata for <ecosystem>/<package> (<version>). failOpen=<value>`.
