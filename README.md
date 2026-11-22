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
| Dependency confusion                    | Blocks public packages named after your internal namespaces (see [Dependency confusion](docs/configuration.md#dependency-confusion-internal-namespaces)) |
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
- **Local-first decision** — one `UNION ALL` query covers company policies, enumerated public vulnerabilities and the API cache; a second indexed lookup evaluates OSV version ranges (npm SemVer, Maven) at the same priority as public vulnerabilities, so company policies always win and a cached ALLOW never masks a known vulnerability.
- **Streaming (16 KB buffer)** — binaries are never loaded into JVM memory, keeping the footprint stable regardless of artifact size.
- **Async audit log** — audit writes never block downloads; overflow is handled with a discard policy.

---

## Quickstart

**Prerequisites:** Java 25+, Docker

```bash
# Start PostgreSQL + a local Gitea instance (auto-provisioned with sample policies)
docker compose up -d

# Run the proxy (connects to localhost:5432 by default)
./gradlew bootRun
```

The proxy listens on **port 8080**. Configure your artifact repository to route outbound traffic through `<host>:8080` (HTTP proxy type), then assign it to your npm, PyPI, and Maven remote repositories.

SilicaProxy decrypts HTTPS traffic (SSL MITM) with a CA generated at startup. Import it into your artifact repository's trust store:

```bash
curl http://localhost:8089/api/monitoring/ca-cert > silicaproxy-ca.crt
```

For production (Docker image, Docker Compose, multiple instances, JAR), see [Deployment](docs/deployment.md).

### Company policies in a nutshell

Allow/block rules live in a Git repository, one YAML file per ecosystem (`npm.yaml`, `pypi.yaml`, `maven.yaml`), synchronized every 10 minutes:

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

Full syntax (version and name patterns, conflict resolution, severity thresholds, internal namespaces): [GitOps policy files](docs/configuration.md#gitops-policy-files).

A blocked download is answered with an HTTP `403` (RFC 7807 JSON) whose `step` field names the pipeline stage that blocked it. See [API Endpoints](docs/api.md).

---

## Documentation

| Topic | Document |
|---|---|
| How each decision source works: company policies, public vulnerabilities, registry metadata, external validation services, live API fallback, fail-open / fail-closed, upstream rate limiting | [docs/data-sources.md](docs/data-sources.md) |
| Development setup, Docker, Docker Compose, multiple instances, JAR | [docs/deployment.md](docs/deployment.md) |
| Every configuration property and environment variable, GitOps policy file format | [docs/configuration.md](docs/configuration.md) |
| REST endpoints, authentication, blocked-response format and `step` values | [docs/api.md](docs/api.md) |
| Observability, health probes, audit log, JVM and PostgreSQL tuning, Prometheus metrics | [docs/operations.md](docs/operations.md) |
| How npm, PyPI and Maven downloads are identified | [docs/PACKAGE_IDENTIFICATION.md](docs/PACKAGE_IDENTIFICATION.md) |

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

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
