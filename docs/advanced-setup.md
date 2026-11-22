# Advanced setup: external scanners

The [Quickstart](../README.md#quickstart) stack runs SilicaProxy and PostgreSQL. Two scanners of
the SilicaProxy project can be added as [external validation services](external-validation.md),
each with its own Compose file in [`docker/`](../docker):

| File | Adds | Mode | What it checks |
|---|---|---|---|
| [`compose.yaml`](../docker/compose.yaml) | SilicaProxy + PostgreSQL | — | the base stack |
| [`compose.packagenameguardian.yaml`](../docker/compose.packagenameguardian.yaml) | [Package-Name-Guardian](https://github.com/Silica-Proxy/Package-Name-Guardian) | sync | the **name**: typosquats of popular packages (`crossenv` for `cross-env`) |
| [`compose.packagebehaviorguardian.yaml`](../docker/compose.packagebehaviorguardian.yaml) | [Package-Behavior-Guardian](https://github.com/Silica-Proxy/Package-Behavior-Guardian) | async | the **content**: static analysis of what a version does (install scripts, credential theft, payloads) |

Every file uses the `latest` images and the **same PostgreSQL server**, with one database per
service (`db_silica`, `db_packagenameguardian`, `db_packagebehaviorguardian`).

```
                      ┌───────────────────────────── Docker network "silicaproxy" ─┐
artifact repository ─►│ silicaproxy:8080 ──sync──► packagenameguardian:8100        │
                      │      ▲          ──async─► packagebehaviorguardian:8101     │
                      │      └── callback ─────────────────┘                       │
                      │                    postgresdb:5432 (3 databases)           │
                      └────────────────────────────────────────────────────────────┘
```

## Start

In `docker/.env` (copied from `.env.example`), set the base values of the Quickstart plus one key
per scanner. Each key is shared by SilicaProxy and its scanner:

```bash
PACKAGENAMEGUARDIAN_API_KEY=<random value>
PACKAGEBEHAVIORGUARDIAN_API_KEY=<random value>
```

Then combine the files you want:

```bash
cd docker
docker compose -f compose.yaml -f compose.packagenameguardian.yaml up -d          # name check only
docker compose -f compose.yaml -f compose.packagebehaviorguardian.yaml up -d      # content check only
docker compose -f compose.yaml -f compose.packagenameguardian.yaml \
               -f compose.packagebehaviorguardian.yaml up -d                      # both
```

To avoid repeating the `-f` options, list the files once in `.env` (`;` instead of `:` on
Windows); `docker compose up -d`, `ps`, `logs` and `down` then use all of them:

```bash
COMPOSE_FILE=compose.yaml:compose.packagenameguardian.yaml:compose.packagebehaviorguardian.yaml
```

At startup, SilicaProxy logs every external validation service with its effective settings:

```bash
docker compose logs silicaproxy | grep "External validation service"
```

## Package-Name-Guardian (sync)

SilicaProxy asks it about every package it has not decided on yet, and waits up to 1 second for
the answer. The name is compared with the 10,000 most popular packages of its ecosystem:

```bash
curl -x http://localhost:8080 --cacert silicaproxy-ca.crt -o /dev/null -w '%{http_code}\n' \
  https://registry.npmjs.org/cross-env/-/cross-env-7.0.3.tgz        # 200
curl -x http://localhost:8080 --cacert silicaproxy-ca.crt \
  https://registry.npmjs.org/crossenv/-/crossenv-6.1.1.tgz          # 403
```

```json
{"title":"Forbidden","status":403,"step":"EXTERNAL_VALIDATION",
 "detail":"'crossenv' is suspiciously similar to popular npm package 'cross-env'", ...}
```

A legitimate package that looks like a popular one can be allowlisted in the scanner, through an
admin API protected by a separate key (`PACKAGENAMEGUARDIAN_ADMIN_API_KEY`), see its
[README](https://github.com/Silica-Proxy/Package-Name-Guardian#4-allowlist), or with a company
`allow` policy in SilicaProxy.

## Package-Behavior-Guardian (async)

SilicaProxy sends it each new version and does not wait: the scanner downloads the whole version,
analyzes it (GuardDog, malcontent, bytecode rules) and calls SilicaProxy back with its verdict,
a few seconds later for a small package. A version is analyzed once.

The file starts it in **observation mode**, as its authors recommend until false positives have
been measured: verdicts are stored, logged and counted, but never block.

```bash
docker compose logs silicaproxy | grep "callback received"
# ... callback received from packagebehaviorguardian for npm/cross-env@7.0.3: verdict=ALLOWED, reason=Static pass score 20 < 60 (rule set 2)
```

To **enforce** its verdicts, set in `.env`, then `docker compose up -d`:

```bash
PACKAGEBEHAVIORGUARDIAN_BLOCKING=true
PACKAGEBEHAVIORGUARDIAN_FAIL_OPEN=false
```

The first download of a version that was never analyzed is then refused with a temporary `429`
until the verdict arrives; retrying after `Retry-After` gets the real answer:

```
first request        429  Retry-After: 30   "step":"EXTERNAL_VALIDATION_PENDING"
after the callback   200  (or 403 "step":"EXTERNAL_VALIDATION" if the scanner blocked it)
```

Builds that fetch many new versions at once therefore fail the first time: plan for it before
enforcing, and see [Missing verdict](external-validation.md#missing-verdict-fail-closed--429) for
why a `429` is used.

**Host requirements.** GuardDog scans npm and PyPI packages in a Landlock sandbox: Linux 5.13 or
later with `landlock` in `/sys/kernel/security/lsm`, and a seccomp profile that allows it (Docker's
default does). Otherwise every npm/PyPI analysis fails; set
`PACKAGEBEHAVIORGUARDIAN_SCANNERS_GUARDDOG_SANDBOX=false` on the scanner as a last resort. Do not
set `no-new-privileges` on its container. Details in its
[README](https://github.com/Silica-Proxy/Package-Behavior-Guardian#deployment).

Expected findings of legitimate packages (install hooks of `esbuild`, for example) are allowlisted
in a Git repository of their own, like the company policies: see `PACKAGEBEHAVIORGUARDIAN_GITOPS_*`
in its [README](https://github.com/Silica-Proxy/Package-Behavior-Guardian#allowlist-gitops).

## Security trade-off: SSRF protection

The scanners are reached on the private Docker network, and SilicaProxy's SSRF protection blocks
every private address. Both files therefore set `SILICAPROXY_SECURITY_SSRF_PROTECTION_ENABLED=false`,
which lifts the protection for **all** outbound calls, not only the scanners. Keep the Docker
network for these containers only, and do not expose the scanners' ports.

## Upgrading an existing installation

The three databases are created on the **first** start of PostgreSQL only. With a `postgres-data`
volume created before the scanners' databases were listed, create the missing one by hand:

```bash
docker compose exec postgresdb psql -U postgres -c 'CREATE DATABASE db_packagebehaviorguardian'
```
