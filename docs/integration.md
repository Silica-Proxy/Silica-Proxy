# Connecting an artifact repository

SilicaProxy is meant to sit behind an artifact repository (Nexus, Artifactory, or any repository
manager that can use an outbound HTTP proxy). The repository's **remote / proxy repositories**
fetch from the public registries through SilicaProxy; your **hosted** repositories do not.

```
npm / pip / Maven clients
        │
        ▼
Artifact repository ── hosted repositories (internal packages, never proxied)
        │ remote repositories (npm, PyPI, Maven Central…)
        │ outbound HTTP proxy = <silicaproxy-host>:8080
        ▼
SilicaProxy ──► registry.npmjs.org, pypi.org, files.pythonhosted.org, repo1.maven.org…
```

## 1. Point the repository's outbound proxy at SilicaProxy

SilicaProxy listens on **port 8080** (`silicaproxy.proxy.port`) and accepts both plain HTTP proxy
requests and `CONNECT` tunnels for HTTPS.

- Declare `<silicaproxy-host>:8080` as an **HTTP proxy** in the repository manager, for HTTP and
  HTTPS. In Nexus 3 this is a global setting (*System > HTTP*); in Artifactory, a proxy is defined
  once and selected per remote repository. Menu names vary between versions.
- Apply it to the remote repositories of the ecosystems SilicaProxy checks: **npm**, **PyPI** and
  **Maven** (including the Gradle Plugin Portal, which is a Maven repository).
- **Exclude internal hosts** from the proxy (the repository manager's own host, internal Git or
  registries): they gain nothing from going through SilicaProxy, and the
  [dependency confusion rules](policies.md#dependency-confusion-internal-namespaces) would block
  internal packages fetched that way.

Requests for other ecosystems still go through, but SilicaProxy cannot identify them and relays
them without any check (counted in `silicaproxy.controller.security.bypass` with
`ecosystem="unknown"`, see [Metrics](operations.md#metrics)).

## 2. Trust the SilicaProxy CA

To inspect HTTPS downloads, SilicaProxy decrypts the `CONNECT` tunnels with its own certificate
authority (SSL MITM). The repository manager must trust that CA, or every HTTPS fetch fails with a
certificate error.

1. Make the CA permanent first: set `silicaproxy.ssl-mitm.ca-keystore-path` (and its password) on
   a persistent volume. Without it, a new CA is generated at each restart and must be imported
   again (see [Deployment](deployment.md#production--docker)).
2. Download the certificate (PEM):
   ```bash
   curl -H "Authorization: Bearer $SILICAPROXY_API_KEY_READ" \
     http://<silicaproxy-host>:8080/api/monitoring/ca-cert > silicaproxy-ca.crt
   ```
   The endpoint needs the read (or action) API key unless
   `silicaproxy.security.api-auth.enabled` is `false` (see [API](api.md)).
3. Import it into the trust store the repository manager uses for outbound connections (the
   SSL certificates screen of Nexus 3, the trusted certificates of Artifactory, or the JVM trust
   store), then restart or reload as your repository manager requires.

Monitor the CA expiry with `silicaproxy.ssl.mitm.ca.seconds_until_expiry`: when the CA is renewed,
the new certificate must be imported everywhere.

## 3. Check that downloads go through

Download a package through the repository manager, then look for it in SilicaProxy:

```bash
curl -H "Authorization: Bearer $SILICAPROXY_API_KEY_READ" \
  "http://<silicaproxy-host>:8080/api/packages/search?packageName=lodash&ecosystem=npm"
```

`silicaproxy.controller.decisions` should increase for each first download. A repository manager
only fetches on a cache miss: a package it already holds is served from its cache and never
reaches SilicaProxy. Packages cached **before** SilicaProxy was put in place are therefore not
re-checked until they leave that cache.

## What the repository manager receives

| SilicaProxy answers | Meaning | Effect on the repository manager |
|---|---|---|
| `200` + the artifact | allowed | cached and served as usual |
| `403` (RFC 7807 JSON) | blocked for good (`step` gives the reason, see [API](api.md)) | the client's download fails; the repository may also remember the failure for a while |
| `429` + `Retry-After` | temporarily blocked: a fail-closed external scan is pending, or an upstream is rate-limiting | the client's download fails now; a later retry gets the real verdict |

Package **metadata** (npm packuments, the PyPI simple index, `maven-metadata.xml`) is relayed
without a check: a client can resolve a blocked version, the block happens when it downloads the
artifact. This is why a blocked version may still appear in `npm view` or in a resolved lockfile.

SilicaProxy answers `429` rather than `403` or `503` for temporary blocks on purpose: a `403`
may stay in the repository's negative cache after the scan allowed the package, and a `5xx` can
make the repository manager mark the whole remote repository as offline (see
[External validation](external-validation.md#missing-verdict-fail-closed--429)).

## Identifying who downloaded a package

Behind a repository manager, the audit log records the repository manager, not the end client. To
tell remote repositories apart, add a static `X-Silica-Client` header on each remote repository
when your repository manager supports custom headers, or a User-Agent suffix. If an HTTP reverse
proxy or load balancer sits in front of SilicaProxy, list it in
`silicaproxy.proxy.trusted-proxies`. Details: [Client identity in the audit
log](operations.md#client-identity-in-the-audit-log).

## Related settings

| Setting | When you need it |
|---|---|
| `silicaproxy.proxy.http-only-hosts` | an internal registry without TLS (by default, plain `http://` requests are upgraded to `https://`) |
| `silicaproxy.corporate-proxy.*` | SilicaProxy itself must go through a corporate proxy to reach the internet |
| `silicaproxy.registries.*-url` | registry metadata must be read from a mirror instead of the public registries |

All of them are described in the [Configuration reference](configuration.md#full-variable-table).
