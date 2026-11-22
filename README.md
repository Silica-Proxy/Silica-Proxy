![Logo](logo.png "Logo")

# SilicaProxy — Artifact Firewall Proxy

SilicaProxy is a **security proxy for artifact repositories** that intercepts every package download and blocks vulnerable, deprecated, or newly published packages before they reach your builds.

It sits between your artifact repository and the public registries (npm, PyPI, Maven Central) and makes a security decision on each package — with minimal overhead on your CI/CD pipelines and dependency resolution.

---

## Why SilicaProxy?

| Threat                                  | How SilicaProxy helps |
|-----------------------------------------|---|
| Known CVEs (Log4Shell, ShaiHulud, etc.) | Blocks packages matching local vulnerability databases (OSV, GHSA, GitLab Advisory, OpenSSF) |
| Typosquatting / supply-chain attacks    | Quarantines packages published less than N days ago |
| Deprecated / yanked packages            | Blocks packages flagged as deprecated (npm) or yanked (PyPI) |
| Custom internal rules                   | Company-level allow/block list synchronized from a Git repository (GitOps) |
| Dependency confusion                    | Blocks public packages named after your internal namespaces (see [Dependency confusion](docs/policies.md#dependency-confusion-internal-namespaces)) |
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
┌─────────────────────────────────┐
│   ProxyController               │  Spring Boot / Tomcat (port 8089, internal)
│   PackageIdentificationService  │  package name, version, ecosystem (URL → npm headers → packument index)
│   SecurityService               │  orchestrates the decision pipeline
└────────┬────────────────────────┘
         │
    ┌────┴──────────────────────────────┐
    │         Decision pipeline         │
    │                                   │
    │  1. company_policies   (priority 1)│  ← GitOps YAML rules
    │  2. public_vulnerabilities (prio 2)│  ← OSV / GHSA / GitLab / OpenSSF
    │  3. api_cache          (priority 3)│  ← cached live API results
    │  (UNION ALL + OSV range lookup)    │
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

**Key design choices:**
- **Virtual threads (Project Loom / Java 25)** — thousands of concurrent downloads with near-zero overhead per connection.
- **Local-first decision** — one `UNION ALL` query covers company policies, enumerated public vulnerabilities and the API cache; a second indexed lookup evaluates OSV version ranges (npm SemVer, Maven) at the same priority as public vulnerabilities, so company policies always win and a cached ALLOW never masks a known vulnerability.
- **Streaming (16 KB buffer)** — binaries are never loaded into JVM memory, keeping the footprint stable regardless of artifact size.
- **Async audit log** — audit writes never block downloads; overflow is handled with a discard policy.

---

## Quickstart

**Prerequisites:** Docker with the Compose plugin. Pre-built images are on [Docker Hub](https://hub.docker.com/r/silicaproxy/silicaproxy).

### 1. Start SilicaProxy and its database

```bash
git clone https://github.com/Silica-Proxy/Silica-Proxy.git
cd Silica-Proxy/docker
cp .env.example .env   # set POSTGRES_PASSWORD, SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD, SILICAPROXY_API_KEY_ACTION
docker compose up -d
docker compose ps      # wait until silicaproxy is "healthy"
```

SilicaProxy listens on **port 8080**: it is both the proxy and the REST API. Check its health with the action key you put in `.env`:

```bash
export KEY=<SILICAPROXY_API_KEY_ACTION>
curl -H "Authorization: Bearer $KEY" http://localhost:8080/api/monitoring/health
```

### 2. Try it

SilicaProxy inspects HTTPS downloads with its own certificate authority (SSL MITM). Download the CA, then fetch a clean package and a vulnerable one through the proxy:

```bash
curl -H "Authorization: Bearer $KEY" http://localhost:8080/api/monitoring/ca-cert > silicaproxy-ca.crt

# allowed: 200
curl -x http://localhost:8080 --cacert silicaproxy-ca.crt -o /dev/null -w '%{http_code}\n' \
  https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz

# blocked: 403, CVE-2021-44906 (CVSS 9.8)
curl -x http://localhost:8080 --cacert silicaproxy-ca.crt \
  https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz
```

```json
{"type":"about:blank","title":"Forbidden","status":403,
 "detail":"The package contains a vulnerability reported by external API OSV (GHSA-xvch-5gv4-984h).",
 "instance":"","step":"OSV_LIVE","package":"minimist","version":"1.2.5","ecosystem":"npm","error":"SecurityBlocked"}
```

The `step` field names the check that blocked the package (see [API](docs/api.md)). The local vulnerability database is filled by a nightly synchronization (2:00); until then, unknown packages are checked against the OSV and deps.dev live APIs.

### 3. Connect your artifact repository

Declare `<silicaproxy-host>:8080` as the outbound HTTP proxy of your npm, PyPI and Maven remote repositories, and import `silicaproxy-ca.crt` into the repository manager's trust store. Step by step: [Integration](docs/integration.md).

### 4. Add your company policies

Allow/block rules live in a Git repository, one file per ecosystem at its root (`npm.yaml`, `pypi.yaml`, `maven.yaml`), synchronized every 10 minutes:

```yaml
rules:
  - package: "event-stream"
    version: "3.3.6"
    action: "block"
    reason: "Supply-chain attack (flatmap-stream, Nov 2018)"

  - package: "minimist"
    version: "1.2.5"
    action: "allow"
    reason: "Temporary exception while migrating to 1.2.8 — ticket SEC-123"
    expires: "2026-12-31"
```

Point SilicaProxy at it in `.env` (add `SILICAPROXY_GITOPS_CLONE_TOKEN` for a private repository), then apply with `docker compose up -d`:

```bash
SILICAPROXY_GITOPS_ENABLED=true
SILICAPROXY_GITOPS_REPOSITORY_URL=https://git.example.com/devops/policies.git
```

Full syntax (version and name patterns, conflict resolution, severity thresholds, internal namespaces): [Company policies](docs/policies.md).

To add the Package-Name-Guardian (typosquatting) and Package-Behavior-Guardian (malicious behavior) scanners, see [Advanced setup](docs/advanced-setup.md).

Production setup (`docker run`, several instances, JAR, memory): [Deployment](docs/deployment.md). To build and run from source, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Documentation

| Topic | Document |
|---|---|
| Connecting Nexus, Artifactory or another artifact repository: outbound proxy, CA trust, what a 403 / 429 means | [Integration](docs/integration.md) |
| Running in production: `docker run`, several instances, JAR, memory | [Deployment](docs/deployment.md) |
| Why a package was blocked, diagnostic endpoints, making an exception, common problems | [Troubleshooting](docs/troubleshooting.md) |
| Writing allow/block rules: version and name patterns, conflicts, severity thresholds, internal namespaces | [Company policies](docs/policies.md) |
| The decision pipeline, fail-open / fail-closed, upstream rate limiting, vulnerability sources, live API fallback | [How it works](docs/how-it-works.md) |
| Age-based quarantine and deprecation checks, publication date resolution | [Quarantine](docs/quarantine.md) |
| Plugging in an SBOM scanner, licence checker or proprietary scanner (sync or async) | [External validation](docs/external-validation.md) |
| How npm, PyPI and Maven downloads are identified | [Package identification](docs/package-identification.md) |
| Every configuration property and environment variable | [Configuration](docs/configuration.md) |
| REST endpoints, authentication, blocked-response format and `step` values | [API](docs/api.md) |
| Observability, health probes, audit log, JVM and PostgreSQL tuning, Prometheus metrics | [Operations](docs/operations.md) |
| Adding the Package-Name-Guardian and Package-Behavior-Guardian scanners with Docker Compose | [Advanced setup](docs/advanced-setup.md) |

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md), which also describes the package structure. To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Attribution requirement
If you use SilicaProxy in your project, product, or service, you **must** include the following attribution in a visible location (e.g., UI footer, documentation, or "About" page):

> "Secured by SilicaProxy (https://github.com/Silica-Proxy/Silica-Proxy)"

This is a **binding requirement** of the [Apache 2.0 License](LICENSE).

## Disclaimer
SilicaProxy is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software, its use, or any collateral damage (including but not limited to server downtime, data loss, or system bugs) resulting from the use of this software.
By using SilicaProxy, you agree to these terms and use this tool entirely at your own risk.


## License

[Apache License 2.0](LICENSE)
