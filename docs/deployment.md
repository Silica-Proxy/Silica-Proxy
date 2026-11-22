# Deployment

## Development

**Prerequisites:** Java 25+, Docker

```bash
# Start PostgreSQL + a local Gitea instance (auto-provisioned with sample policies)
docker compose up -d

# Run the proxy (connects to localhost:5432 by default)
./gradlew bootRun
```

The proxy listens on **port 8080**. Configure your artifact repository to route outbound traffic through `<host>:8080` (HTTP proxy type), then assign it to your npm, PyPI, and Maven remote repositories.

> **HTTPS repositories:** SilicaProxy performs SSL MITM. It generates a CA at startup that must be imported into your artifact repository's trust store. Retrieve it with:
> ```bash
> curl http://localhost:8089/api/monitoring/ca-cert > silicaproxy-ca.crt
> ```

---

## Production — Docker

Pre-built images are available on [Docker Hub](https://hub.docker.com/r/silicaproxy/silicaproxy).

All configuration is passed as environment variables. Minimum required set:

```bash
docker run -d \
  -p 8080:8080 \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://your-db:5432/security_db \
  -e SPRING_DATASOURCE_USERNAME=prod_user \
  -e SPRING_DATASOURCE_PASSWORD=prod_password \
  -e SILICAPROXY_GITOPS_REPOSITORY_URL=https://git.yourcompany.com/devops/policies.git \
  -e SILICAPROXY_GITOPS_CLONE_TOKEN=yourtoken \
  -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/data/silicaproxy-ca.p12 \
  -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=changeme \
  -v /data/silicaproxy:/data \
  silicaproxy/silicaproxy
```

> **Memory:** allocate at least 2 GB to the container — see [Recommended JVM flags](operations.md#recommended-jvm-flags-production) to tune the JVM via `JDK_JAVA_OPTIONS`.

> **CA keystore persistence:** without `-e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH`, a new CA is generated at every container restart — breaking your artifact repository's SSL trust until the certificate is re-imported. Mount a volume and set this variable in production.

---

## Production — Docker Compose

[`docker/compose.yaml`](../docker/compose.yaml) starts SilicaProxy with a dedicated PostgreSQL 18, the CA keystore and the logs on named volumes, and the API protected by keys:

```bash
cd docker
cp .env.example .env   # set the passwords, API keys and GitOps repository URL
docker compose up -d
```

- Only port `8080` is published (`SILICAPROXY_PROXY_PORT` to change the host port): it serves both the proxy and the REST API / actuator.
- Retrieve the CA certificate to import into your artifact repository with `curl -H "Authorization: Bearer $SILICAPROXY_API_KEY_ACTION" http://localhost:8080/api/monitoring/ca-cert > silicaproxy-ca.crt` (or with `SILICAPROXY_API_KEY_READ`, optional, if you set one).
- [PackageNameGuardian](https://hub.docker.com/r/silicaproxy/packagenameguardian) (typosquatting detection, called as a sync [external validation service](data-sources.md#4-external-validation-services--on-demand-sync-or-async)) is optional: set `PACKAGENAMEGUARDIAN_ENABLED=true`, `PACKAGENAMEGUARDIAN_API_KEY` and `SILICAPROXY_SECURITY_SSRF_PROTECTION_ENABLED=false` in `.env` (the service is reached on the private Docker network, which the SSRF protection blocks), then run `docker compose --profile packagenameguardian up -d`.
- The databases (`db_silica`, `db_packagenameguardian`) are created by [`docker/postgres/init-multiple-dbs.sh`](../docker/postgres/init-multiple-dbs.sh) on the first start only, when the `postgres-data` volume is empty.

The `compose.yaml` at the repository root is for [development](#development) only.

---

## Production — Multiple instances / load balancing

All instances behind a load balancer **must use the same CA keystore file** — otherwise each one generates its own CA, and clients get random SSL trust failures depending which backend they land on.

**With shared storage** (NFS/EFS, a `ReadWriteMany` PVC, a bind-mounted volume): point every instance's `ca-keystore-path` at the same shared file. Instances can be started in any order, including all at once — CA generation is coordinated through a distributed lock (backed by the same PostgreSQL database every instance already uses, via the ShedLock table). Whichever instance starts first wins the lock, generates the CA and saves it; the others wait for the lock — or notice the file appear — and load it instead of generating their own. No staggered rollout is required.

**Without shared storage** (independent servers, no shared filesystem): the lock only protects instances that read and write the *same file* — with no shared file, it can't help, so generate the CA once and copy the same file everywhere.

1. Generate it with a throwaway instance against any reachable Postgres:
   ```bash
   docker run --rm -d --name ca-seed \
     -e SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/security_db \
     -e SPRING_DATASOURCE_USERNAME=postgres -e SPRING_DATASOURCE_PASSWORD=postgres \
     -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/data/silicaproxy-ca.p12 \
     -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=<strong-password> \
     -v "$(pwd)/ca-seed:/data" \
     silicaproxy/silicaproxy
   docker rm -f ca-seed   # once it logged "CA certificate generated and saved"
   ```
2. Copy `ca-seed/silicaproxy-ca.p12` to the same path on every server (`scp`, config management, secrets manager), with the same `ca-keystore-password`. Never generate it again per-server.
3. Start SilicaProxy on each server pointing at the copied file — since it already exists, every instance loads it instead of generating its own.

Either way, back up the keystore file: losing it means every server mints a new, different CA on its next restart, breaking SSL trust everywhere until it's re-imported.

---

## Production — JAR

```bash
# Build
./gradlew bootJar
# Output: build/libs/silicaproxy.jar
```

Place an `application.yaml` next to the JAR (Spring Boot picks it up automatically), or point to it explicitly:

```bash
java \
  -XX:+UseG1GC \
  -XX:MaxRAMPercentage=75.0 \
  -XX:+UseCompactObjectHeaders \
  -XX:+UseStringDeduplication \
  -Dsun.net.inetaddr.ttl=60 \
  -jar silicaproxy.jar \
  --spring.config.location=file:./application.yaml
```

Minimal `application.yaml` for production:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://your-db:5432/security_db
    username: prod_user
    password: prod_password

silicaproxy:
  gitops:
    repository-url: "https://git.yourcompany.com/devops/policies.git"
    clone-token: "yourtoken"
  ssl-mitm:
    ca-keystore-path: "/data/silicaproxy-ca.p12"
    ca-keystore-password: "changeme"
```

All other settings default to the values listed in the table below.
