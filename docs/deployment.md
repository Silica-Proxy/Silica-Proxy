# Deployment

SilicaProxy ships as a Docker image ([Docker Hub](https://hub.docker.com/r/silicaproxy/silicaproxy)). The quickest way to run it is the Docker Compose stack, see the [Quickstart](../README.md#quickstart). To build and run it from source, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Production — Docker

Without Docker Compose, run PostgreSQL and SilicaProxy on a shared Docker network. Every setting is an environment variable (see the [Configuration reference](configuration.md#full-variable-table)):

```bash
docker network create silicaproxy

docker run -d --name silicaproxy-db --network silicaproxy \
  -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=security_db \
  -v silicaproxy-db:/var/lib/postgresql \
  postgres:18

docker run -d --name silicaproxy --network silicaproxy -p 8080:8080 \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://silicaproxy-db:5432/security_db \
  -e SPRING_DATASOURCE_PASSWORD=change-me \
  -e SILICAPROXY_GITOPS_ENABLED=false \
  -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/app/certs/silicaproxy-ca.p12 \
  -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=change-me \
  -e SILICAPROXY_API_KEY_ACTION=change-me-action \
  -v silicaproxy-certs:/app/certs \
  silicaproxy/silicaproxy
```

- With an existing PostgreSQL, drop the first container and point `SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME` (default `postgres`) and `SPRING_DATASOURCE_PASSWORD` at it.
- `SILICAPROXY_API_KEY_ACTION` is required to call the REST API (CA download, health, forced syncs): the API is protected by default.
- To enable company policies, replace `SILICAPROXY_GITOPS_ENABLED=false` with `SILICAPROXY_GITOPS_ENABLED=true` and `SILICAPROXY_GITOPS_REPOSITORY_URL=<repository>` (plus `SILICAPROXY_GITOPS_CLONE_TOKEN` for a private repository).

> **Memory:** allocate at least 2 GB to the container — see [Recommended JVM flags](operations.md#recommended-jvm-flags-production) to tune the JVM via `JDK_JAVA_OPTIONS`.

> **CA keystore persistence:** without `SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH` on a volume, a new CA is generated at every container restart — breaking your artifact repository's SSL trust until the certificate is re-imported. Mount a volume and set this variable in production.

---

## Production — Docker Compose

[`docker/compose.yaml`](../docker/compose.yaml) starts SilicaProxy with a dedicated PostgreSQL 18, the CA keystore and the logs on named volumes, and the API protected by keys:

```bash
cd docker
cp .env.example .env   # set the passwords and the action API key
docker compose up -d
```

- Only port `8080` is published (`SILICAPROXY_PROXY_PORT` to change the host port): it serves both the proxy and the REST API / actuator.
- Retrieve the CA certificate to import into your artifact repository with `curl -H "Authorization: Bearer $SILICAPROXY_API_KEY_ACTION" http://localhost:8080/api/monitoring/ca-cert > silicaproxy-ca.crt` (or with `SILICAPROXY_API_KEY_READ`, optional, if you set one).
- External scanners (Package-Name-Guardian, Package-Behavior-Guardian) are added by their own Compose files next to `compose.yaml`: see [Advanced setup](advanced-setup.md).
- One PostgreSQL server holds every database (`db_silica`, `db_packagenameguardian`, `db_packagebehaviorguardian`), created by [`docker/postgres/init-multiple-dbs.sh`](../docker/postgres/init-multiple-dbs.sh) on the first start only, when the `postgres-data` volume is empty.
- Company policies are off until `SILICAPROXY_GITOPS_ENABLED=true` and `SILICAPROXY_GITOPS_REPOSITORY_URL` are set in `.env`; run `docker compose up -d` again to apply.

The `compose.yaml` at the repository root is for development only (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

---

## Production — Multiple instances / load balancing

All instances behind a load balancer **must use the same CA keystore file** — otherwise each one generates its own CA, and clients get random SSL trust failures depending which backend they land on.

**With shared storage** (NFS/EFS, a `ReadWriteMany` PVC, a bind-mounted volume): point every instance's `ca-keystore-path` at the same shared file. Instances can be started in any order, including all at once — CA generation is coordinated through a distributed lock (backed by the same PostgreSQL database every instance already uses, via the ShedLock table). Whichever instance starts first wins the lock, generates the CA and saves it; the others wait for the lock — or notice the file appear — and load it instead of generating their own. No staggered rollout is required.

**Without shared storage** (independent servers, no shared filesystem): the lock only protects instances that read and write the *same file* — with no shared file, it can't help, so generate the CA once and copy the same file everywhere.

1. Generate it with a throwaway instance against any reachable PostgreSQL (here the `silicaproxy-db` container of the [Docker](#production--docker) example):
   ```bash
   docker run -d --name ca-seed --network silicaproxy \
     -e SPRING_DATASOURCE_URL=jdbc:postgresql://silicaproxy-db:5432/security_db \
     -e SPRING_DATASOURCE_PASSWORD=change-me \
     -e SILICAPROXY_GITOPS_ENABLED=false \
     -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/app/certs/silicaproxy-ca.p12 \
     -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=<strong-password> \
     silicaproxy/silicaproxy
   # once `docker logs ca-seed` shows "CA certificate generated and saved":
   docker cp ca-seed:/app/certs/silicaproxy-ca.p12 .
   docker rm -f ca-seed
   ```
   The keystore is written inside the container, then copied out: the image runs as a non-root user (`appuser`), which cannot write into a host directory that Docker creates as root for a bind mount.
2. Copy `silicaproxy-ca.p12` to every server (`scp`, config management, secrets manager), with the same `ca-keystore-password`. Never generate it again per-server.
3. Mount it on each server and point SilicaProxy at it. Since it already exists, every instance loads it instead of generating its own; read-only is enough:
   ```bash
   -v /etc/silicaproxy/silicaproxy-ca.p12:/app/certs/silicaproxy-ca.p12:ro \
   -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PATH=/app/certs/silicaproxy-ca.p12 \
   -e SILICAPROXY_SSL_MITM_CA_KEYSTORE_PASSWORD=<strong-password>
   ```
   The file must be readable by the container user (for example mode `644`).

Either way, back up the keystore file: losing it means every server mints a new, different CA on its next restart, breaking SSL trust everywhere until it's re-imported.

---

## Production — JAR

**Prerequisites:** Java 25 to run it; the repository to build it.

```bash
# Build
./gradlew bootJar
# Output: build/libs/silicaproxy-<version>.jar (e.g. silicaproxy-2.0.0.jar)
```

Your settings go in an `application.yaml` that **adds to** the defaults shipped in the JAR. Spring Boot reads it automatically from the directory `java` is started from (or its `config/` subdirectory); to keep it elsewhere, pass it with `--spring.config.additional-location`:

```bash
java \
  -XX:+UseG1GC \
  -XX:MaxRAMPercentage=75.0 \
  -XX:+UseCompactObjectHeaders \
  -XX:+UseStringDeduplication \
  -Dsun.net.inetaddr.ttl=60 \
  -jar silicaproxy-<version>.jar \
  --spring.config.additional-location=file:/etc/silicaproxy/application.yaml
```

> Do not use `--spring.config.location`: it **replaces** the defaults of the JAR instead of adding to them, and SilicaProxy fails to start (`Failed to bind properties under 'silicaproxy'`).

Minimal `application.yaml`:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://your-db:5432/security_db
    username: postgres
    password: change-me

silicaproxy:
  security:
    api-auth:
      key-action: "change-me-action"     # required to call the REST API (CA download, health…)
  ssl-mitm:
    ca-keystore-path: "/var/lib/silicaproxy/silicaproxy-ca.p12"   # must be writable by the user running java
    ca-keystore-password: "change-me"
  gitops:
    enabled: false                       # true + repository-url (and clone-token) to enable company policies
```

All other settings default to the values listed in the [Configuration reference](configuration.md#full-variable-table).
