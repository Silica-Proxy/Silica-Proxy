# Troubleshooting

## Why was my package blocked?

### 1. Read the response

A blocked download returns an RFC 7807 JSON body. Your build tool may only print the status code;
the body is also visible in the artifact repository's logs, or by downloading the artifact
through SilicaProxy directly.

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "detail": "Forbidden — use child_process directly",
  "instance": "",
  "step": "COMPANY_POLICY",
  "package": "shelljs",
  "version": "0.8.5",
  "ecosystem": "npm",
  "error": "SecurityBlocked"
}
```

`step` names the check that blocked the package, and `detail` gives its reason: the `reason` of
the company policy rule, the advisory ids, the publication age… The full list of `step` values is in [API](api.md).

**`403` or `429`?** A `403` is a real verdict. A `429` with `Retry-After` is temporary: an
external scan is still running or unavailable (`EXTERNAL_VALIDATION_PENDING`,
`EXTERNAL_VALIDATION_UNAVAILABLE`), or an upstream is rate-limiting the proxy
(`UPSTREAM_THROTTLED`). Retry after the delay.

### 2. Find the cause for your `step`

| `step` | What to check | How to unblock (if legitimate) |
|---|---|---|
| `COMPANY_POLICY` | the rule that matched: `GET /api/policies/evaluate` (below) | change the rule in the GitOps repository |
| `PUBLIC_VULN`, `PUBLIC_VULN_ANOMALY` | the advisory in `detail`, and the local data: `GET /api/packages/search` | upgrade to a fixed version, or add a temporary `allow` rule with `expires` |
| `PUBLIC_VULN_MALWARE` | the `MAL-*` / OpenSSF advisory | do not unblock: replace the package |
| `API_CACHE`, `OSV_LIVE`, `DEPS_DEV` | the advisory ids in `detail` | upgrade, or add an `allow` rule (a cached BLOCK otherwise lasts `api-cache.block-verdict-ttl-minutes`, 7 days by default) |
| `REGISTRY_QUARANTINE` | publication date and threshold in `detail` | wait until the version is old enough, or add a temporary `allow` rule (see [Quarantine](quarantine.md)) |
| `REGISTRY_DEPRECATION` | the deprecation / yank message in `detail` | use another version |
| `REGISTRY_ERROR`, `REGISTRY_NOT_FOUND`, `API_FALLBACK_ERROR` | registry or OSV/deps.dev reachability, from SilicaProxy | none needed once the upstream answers again: these verdicts are never cached |
| `EXTERNAL_VALIDATION` | the service named in `detail` | see the service's own report (the verdict is permanent, see below) |
| `UNIDENTIFIED_ARTIFACT` | the download URL: npm tarball neither recognized from its URL nor from a packument relayed earlier | see [npm tarball identification](package-identification.md#npm-tarball-identification) |

### 3. Ask SilicaProxy

These endpoints need the read API key (`Authorization: Bearer <key-read>`), see [API](api.md).

**Everything SilicaProxy knows locally about a package** — company policies, public
vulnerabilities and `api_cache` entries:

```bash
curl -H "Authorization: Bearer $KEY_READ" \
  "http://<host>:8080/api/packages/search?packageName=lodash&ecosystem=npm&version=4.17.20"
```

`version` is an exact version; use `versionRegex` instead to match several (not both).

**Which company policy applies**, as stored in the database:

```bash
curl -H "Authorization: Bearer $KEY_READ" \
  "http://<host>:8080/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.20"
```

The response gives the `decision` (`ALLOWED`, `BLOCKED` or `NO_MATCH`) and every matching rule,
with its specificity and the one that `wins`.

**Test a rule before committing it** to the GitOps repository (nothing is stored):

```bash
curl -X POST -H "Authorization: Bearer $KEY_READ" -H "Content-Type: application/json" \
  "http://<host>:8080/api/policies/simulate" -d '{
    "ecosystem": "npm", "packageName": "lodash", "version": "4.17.20",
    "policies": [
      { "packageName": "lodash", "versionPattern": "*",       "policyAction": "BLOCK", "reason": "test" },
      { "packageName": "lodash", "versionPattern": "4.17.20", "policyAction": "ALLOW", "reason": "test" }
    ]
  }'
```

`versionPattern` uses the YAML syntax (`*`, `1.x`); `policyAction` is `ALLOW` or `BLOCK`, in
upper case.

## Making an exception

Add a rule to the GitOps repository, preferably with an end date, so that the exception does not
outlive the reason it was granted:

```yaml
rules:
  - package: "lodash"
    version: "4.17.20"
    action: "allow"
    reason: "Exception until the migration to 4.17.21 — ticket SEC-123"
    expires: "2026-12-31"
```

A company policy wins over every other source, including quarantine, vulnerabilities and external
validation verdicts. The rules are synchronized every 10 minutes
(`silicaproxy.gitops.sync-interval-minutes`); to apply a change immediately:

```bash
curl -X POST -H "Authorization: Bearer $KEY_ACTION" http://<host>:8080/api/gitops/sync/force
```

See [Company policies](policies.md) for the rule syntax and how conflicts are resolved.

## The package is still blocked after a change

- **The artifact repository cached the failure.** Some repository managers remember a failed
  download for a while; clear that entry or wait for its expiry.
- **The client cached it.** Clear the client's cache (`npm cache clean --force`, `pip cache purge`,
  `~/.m2/repository/...lastUpdated` files for Maven).
- **The rule did not sync.** Check `GET /api/policies/evaluate`, the `silicaproxy.gitops.sync.runs`
  metric, and the logs: an `allow` rule with an unreadable `expires` is rejected.
- **A permanent external validation verdict.** A `BLOCKED` verdict from a blocking external service
  is stored in `external_validation_verdicts` and never expires. A company `allow` rule overrides
  it; otherwise it can only be removed from the database, by an administrator:
  ```sql
  DELETE FROM external_validation_verdicts
  WHERE ecosystem = 'npm' AND package_name = 'lodash' AND package_version = '4.17.20';
  ```

## Finding who downloaded a package

Every verdict is written to the `proxy_audit_logs` table (package, version, ecosystem,
`decision_source`, `verdict`, `reason`, URL, client address, `User-Agent`, client id):

```sql
SELECT timestamp, verdict, decision_source, client_ip, client_id, user_agent
FROM proxy_audit_logs
WHERE ecosystem = 'npm' AND package_name = 'lodash' AND package_version = '4.17.20'
ORDER BY timestamp DESC;
```

Behind an artifact repository, the client columns identify the repository manager, not the
workstation: see [Client identity in the audit log](operations.md#client-identity-in-the-audit-log).

## Other common problems

| Symptom | Likely cause |
|---|---|
| Every HTTPS download fails with a certificate error | the SilicaProxy CA is not trusted by the artifact repository, or it changed (keystore not persisted). See [Connecting an artifact repository](integration.md#2-trust-the-silicaproxy-ca) |
| Certificate errors on some requests only, with several instances | the instances do not share the same CA keystore. See [Deployment](deployment.md#production--multiple-instances--load-balancing) |
| Packages are never blocked, `decisions` metric stays flat | traffic does not go through SilicaProxy, or it is not identified (`silicaproxy.controller.security.bypass{ecosystem="unknown"}`) |
| `SSRF Blocked: Unable to resolve host …` in the logs, vulnerability syncs failing | the container cannot resolve public host names. Some Docker DNS resolvers (Colima's, for example) do not answer IPv6 (`AAAA`) queries, which the image's musl resolver treats as a failure. Give the container a working DNS server: `dns: [<ip>]` on the `silicaproxy` service, or `--dns <ip>` with `docker run` |
| Many `REGISTRY_ERROR` allows | a registry is unreachable from SilicaProxy: check egress, `corporate-proxy.*`, and `silicaproxy.quarantine.publish_date.unresolved` |
| `401` on the API | missing or wrong `Authorization: Bearer` key; the action key also opens read endpoints, not the reverse |
| Health is `DEGRADED` | a vulnerability or GitOps sync failed or is late: `GET /api/vulnerabilities/sync/status`, see [Health probes](operations.md#health-probes) |
