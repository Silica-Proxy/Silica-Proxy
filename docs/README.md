# SilicaProxy documentation

Start with the [project README](../README.md) for an overview and a quickstart.

## Reference

- [Data sources](data-sources.md) — the decision pipeline, source by source: company policies (GitOps), public vulnerabilities (OSV, GHSA, GitLab, OpenSSF), registry metadata (quarantine, deprecation), external validation services, live API fallback, fail-open / fail-closed, upstream rate limiting.
- [Deployment](deployment.md) — development, Docker, Docker Compose, multiple instances, JAR.
- [Configuration](configuration.md) — every property and environment variable, GitOps policy file format.
- [API](api.md) — REST endpoints, authentication, blocked-response format and `step` values.
- [Operations](operations.md) — observability, health probes, audit log client identity, JVM and PostgreSQL tuning, metrics.
- [Package identification](PACKAGE_IDENTIFICATION.md) — how npm, PyPI and Maven downloads are identified.

## Design notes (French)

- [Mécanisme de quarantaine](QUARANTINE.md) — anti-typosquatting quarantine.
- [NPM quarantine — implémentation précise](NPM_QUARANTINE_DETAILED.md) — npm-specific quarantine layers.
