/*
 * Copyright 2026 SilicaProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.silicaproxy.config;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.silicaproxy.dao.client.OsvClient;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.policy.GitOpsSyncService;
import com.silicaproxy.service.vulnerability.OsvIncrementalSyncService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncScheduler;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.headRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;

// End-to-end validation of every outbound HTTP client category through a real Squid proxy.
//
// Network topology:
//   SilicaProxy (host) → Squid (container) → WireMock (host, via host.testcontainers.internal)
//                      ↘ Gitea (container, via shared Docker network alias "gitea")
//
// Scope configuration:
//   scope.registries=true             → RegistryClient (npm, maven) goes through Squid
//   scope.security-apis=true          → OsvClient (OSV Live API) goes through Squid
//   scope.registries=true             → OsvIncrementalClient (GCS bucket) goes through Squid
//   scope.internal-git-repository=true → JGit (GitOps clone) goes through Squid
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@NullMarked
class CorporateProxyOutboundClientsTest {

    private static final String GITEA_ADMIN_USER = "testadmin";
    private static final String GITEA_ADMIN_PASSWORD = "T3stP@ss!";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static final WireMockServer wireMock =
            new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());

    private static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:18-alpine")
                    .withCommand("postgres",
                            "-c", "shared_buffers=512MB",
                            "-c", "work_mem=16MB",
                            "-c", "max_connections=1000",
                            "-c", "synchronous_commit=off",
                            "-c", "fsync=off");

    // Shared network so that Squid can reach Gitea by its network alias
    private static final Network network = Network.newNetwork();

    @SuppressWarnings("resource")
    private static final GenericContainer<?> squid =
            new GenericContainer<>("ubuntu/squid:6.6-24.04_edge")
                    .withNetwork(network)
                    .withExposedPorts(3128)
                    .withCopyToContainer(
                            MountableFile.forClasspathResource("squid-test.conf"),
                            "/etc/squid/squid.conf")
                    .waitingFor(Wait.forListeningPort());

    @SuppressWarnings("resource")
    private static final GenericContainer<?> gitea =
            new GenericContainer<>(DockerImageName.parse("gitea/gitea:1.26"))
                    .withNetwork(network)
                    .withNetworkAliases("gitea")
                    .withExposedPorts(3000)
                    .withEnv("GITEA__security__INSTALL_LOCK", "true")
                    .withEnv("GITEA__server__DOMAIN", "gitea")
                    .withEnv("GITEA__server__HTTP_PORT", "3000")
                    .withEnv("GITEA__database__DB_TYPE", "sqlite3")
                    .withEnv("GITEA__security__PASSWORD_COMPLEXITY", "off")
                    .withEnv("GITEA__log__LEVEL", "Error")
                    .waitingFor(Wait.forHttp("/api/v1/version")
                            .withStartupTimeout(Duration.ofMinutes(2)));

    private static String adminToken;
    private static String gitopsRepoUrl;
    private static Path gitopsDir;

    static {
        try {
            gitopsDir = Files.createTempDirectory("gitops-proxy-test");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        wireMock.start();
        Testcontainers.exposeHostPorts(wireMock.port());
        postgres.start();
        squid.start();
        gitea.start();
        setupGitea();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);

        // All outbound HTTP flows through Squid. Registry and security-API URLs use
        // host.testcontainers.internal (only resolvable by Squid, not by the host directly).
        String wireMockViaProxy = "http://host.testcontainers.internal:" + wireMock.port();
        registry.add("silicaproxy.registries.npm-url", () -> wireMockViaProxy);
        registry.add("silicaproxy.registries.pypi-url", () -> wireMockViaProxy);
        registry.add("silicaproxy.registries.maven-url", () -> wireMockViaProxy);
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "true");
        registry.add("silicaproxy.api-fallback.osv.url", () -> wireMockViaProxy + "/v1/query");
        registry.add("silicaproxy.osv-incremental.enabled", () -> "true");
        registry.add("silicaproxy.osv-incremental.gcs-base-url", () -> wireMockViaProxy);
        registry.add("silicaproxy.osv-incremental.initial-lookback-hours", () -> "1");

        // Corporate proxy → Squid (host port, both registries and security APIs)
        registry.add("silicaproxy.corporate-proxy.enabled", () -> "true");
        registry.add("silicaproxy.corporate-proxy.host", squid::getHost);
        registry.add("silicaproxy.corporate-proxy.port", () -> squid.getMappedPort(3128));
        registry.add("silicaproxy.corporate-proxy.non-proxy-hosts", () -> "none-matches-anything.invalid");
        registry.add("silicaproxy.corporate-proxy.scope.registries", () -> "true");
        registry.add("silicaproxy.corporate-proxy.scope.security-apis", () -> "true");
        registry.add("silicaproxy.corporate-proxy.scope.external-git-repositories", () -> "false");
        // GitOps repo is at http://gitea:3000/...; GitProxyConfig routes "gitea" host through Squid.
        registry.add("silicaproxy.corporate-proxy.scope.internal-git-repository", () -> "true");

        // GitOps: JGit → Squid → "gitea" (Docker network alias, resolvable by Squid)
        registry.add("silicaproxy.gitops.enabled", () -> "true");
        registry.add("silicaproxy.gitops.repository-url", () -> gitopsRepoUrl);
        registry.add("silicaproxy.gitops.directory-path", () -> gitopsDir.toString());
        registry.add("silicaproxy.gitops.clone-token", () -> adminToken);
        registry.add("silicaproxy.gitops.sync-interval-minutes", () -> "60");

        registry.add("silicaproxy.security.ssrf-protection.enabled", () -> "false");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-path", () -> "");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-password", () -> "");
        registry.add("silicaproxy.proxy.port", () -> 0);
        registry.add("silicaproxy.http-client.connect-timeout-seconds", () -> 10);
        registry.add("silicaproxy.http-client.registries-read-timeout-seconds", () -> 10);
        registry.add("silicaproxy.http-client.security-apis-read-timeout-seconds", () -> 10);
    }

    // Mocked to prevent the scheduler from firing async sync tasks during the test run,
    // which would make unexpected calls to the (not yet stubbed) WireMock endpoints.
    @MockitoBean
    private VulnerabilitySyncScheduler vulnerabilitySyncScheduler;

    private final SecurityService securityService;
    private final OsvClient osvClient;
    private final OsvIncrementalSyncService osvIncrementalSyncService;
    private final GitOpsSyncService gitOpsSyncService;
    private final JdbcClient jdbcClient;

    @Autowired
    CorporateProxyOutboundClientsTest(
            SecurityService securityService,
            OsvClient osvClient,
            OsvIncrementalSyncService osvIncrementalSyncService,
            GitOpsSyncService gitOpsSyncService,
            JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.osvClient = osvClient;
        this.osvIncrementalSyncService = osvIncrementalSyncService;
        this.gitOpsSyncService = gitOpsSyncService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("UPDATE sync_status SET status = 'PENDING', last_end_time = NULL, items_processed = 0"
                + " WHERE job_id LIKE 'osv-%-incremental'").update();
        jdbcClient.sql("TRUNCATE shedlock").update();
        wireMock.resetAll();
    }

    // ── Registries (npm, Maven) ───────────────────────────────────────────────

    @Test
    void shouldAllowNpmPackageWhenRegistryCallTransitsThroughSquid() throws Exception {
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/lodash"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"time": {"4.17.21": "%s"}, "versions": {"4.17.21": {}}}
                                """.formatted(publishedAt))));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("lodash", "4.17.21", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        wireMock.verify(1, getRequestedFor(urlEqualTo("/lodash")));
        Container.ExecResult log = squid.execInContainer("cat", "/var/log/squid/access.log");
        assertThat(log.getStdout()).contains("host.testcontainers.internal");
    }

    @Test
    void shouldAllowMavenPackageWhenRegistryCallTransitsThroughSquid() throws Exception {
        wireMock.stubFor(head(urlEqualTo("/maven2/com/example/mylib/1.0.0/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", "Wed, 16 Nov 2022 13:00:00 GMT")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("com.example:mylib", "1.0.0", "maven");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        wireMock.verify(1, headRequestedFor(urlEqualTo("/maven2/com/example/mylib/1.0.0/")));
        Container.ExecResult log = squid.execInContainer("cat", "/var/log/squid/access.log");
        assertThat(log.getStdout()).contains("host.testcontainers.internal");
    }

    @Test
    void shouldBlockNpmPackageViaPublicVulnDbWithoutContactingProxy() throws Exception {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities
                (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('CVE-PROXY-TEST', 'OSV', 'critical-pkg', 'npm',
                    'Critical bug', 'Details', '["9.9.9"]'::jsonb, 9.8, NOW())
        """).update();

        DecisionResult decision = securityService.getDecision("critical-pkg", "9.9.9", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("PUBLIC_VULN");
        wireMock.verify(0, getRequestedFor(urlEqualTo("/critical-pkg")));
        Container.ExecResult log = squid.execInContainer("cat", "/var/log/squid/access.log");
        assertThat(log.getStdout()).doesNotContain("critical-pkg");
    }

    // ── OSV Live API ──────────────────────────────────────────────────────────

    @Test
    void shouldCheckVulnerabilityViaOsvApiThroughSquid() throws Exception {
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {"vulns": [{"id": "GHSA-PROXY-LIVEAPI-TEST"}]}
                                """)));

        ApiCheckResult result = osvClient.checkVulnerability("lodash", "4.17.19", "npm");

        assertThat(result.vulnerable()).isTrue();
        assertThat(result.httpStatus()).isEqualTo(200);
        wireMock.verify(1, postRequestedFor(urlEqualTo("/v1/query")));
        // Squid access log confirms the OSV API call transited through the proxy
        Container.ExecResult log = squid.execInContainer("cat", "/var/log/squid/access.log");
        assertThat(log.getStdout()).contains("host.testcontainers.internal");
    }

    // ── OSV Incremental (GCS bucket) ─────────────────────────────────────────

    @Test
    void shouldRunOsvIncrementalSyncThroughSquid() throws Exception {
        Instant recent = Instant.now().minus(30, ChronoUnit.MINUTES);
        wireMock.stubFor(get(urlEqualTo("/npm/modified_id.csv"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/plain")
                        .withBody(recent + ",GHSA-PRXY-INCR-0001\n")));
        wireMock.stubFor(get(urlEqualTo("/npm/GHSA-PRXY-INCR-0001.json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(minimalOsvJson("GHSA-PRXY-INCR-0001", "proxy-test-pkg", "npm", "1.0.0"))));
        wireMock.stubFor(get(urlEqualTo("/PyPI/modified_id.csv"))
                .willReturn(aResponse().withHeader("Content-Type", "text/plain").withBody("")));
        wireMock.stubFor(get(urlEqualTo("/Maven/modified_id.csv"))
                .willReturn(aResponse().withHeader("Content-Type", "text/plain").withBody("")));

        osvIncrementalSyncService.runIncrementalSync();

        // WireMock received both the CSV listing and the individual advisory JSON
        wireMock.verify(1, getRequestedFor(urlEqualTo("/npm/modified_id.csv")));
        wireMock.verify(1, getRequestedFor(urlPathMatching("/npm/GHSA-PRXY-INCR-0001\\.json")));
        // The advisory was ingested in the local DB
        Long count = jdbcClient.sql(
                "SELECT count(*) FROM public_vulnerabilities WHERE id = 'GHSA-PRXY-INCR-0001'").query(Long.class).single();
        assertThat(count).isEqualTo(1L);
        // Squid access log confirms GCS calls transited through the proxy
        Container.ExecResult log = squid.execInContainer("cat", "/var/log/squid/access.log");
        assertThat(log.getStdout()).contains("host.testcontainers.internal");
    }

    // ── GitOps (JGit HTTP clone via GitProxyConfig) ───────────────────────────

    @Test
    void shouldCloneGitOpsRepositoryThroughSquid() throws Exception {
        // Delete any local clone from previous runs so a fresh clone is performed
        deleteDirectory(gitopsDir);

        gitOpsSyncService.syncCompanyPolicies();

        // GitOps sync ingested the npm.yaml policy from Gitea into company_policies
        List<Map<String, Object>> policies = jdbcClient.sql(
                "SELECT * FROM company_policies WHERE ecosystem = 'npm' AND updated_by = 'gitops_sync'").query().listOfRows();
        assertThat(policies).isNotEmpty();
        assertThat(policies.get(0).get("package_name")).isEqualTo("lodash");
        assertThat(policies.get(0).get("policy_action")).isEqualTo("BLACKLIST");
        // Squid access log confirms the JGit HTTP clone transited through the proxy to Gitea
        Container.ExecResult log = squid.execInContainer("cat", "/var/log/squid/access.log");
        assertThat(log.getStdout()).contains("gitea");
    }

    // ── Gitea setup helpers ───────────────────────────────────────────────────

    private static void setupGitea() {
        try {
            String giteaBaseUrl = "http://" + gitea.getHost() + ":" + gitea.getMappedPort(3000);

            Container.ExecResult result = gitea.execInContainer(
                    "/sbin/su-exec", "git",
                    "gitea", "admin", "user", "create",
                    "--username", GITEA_ADMIN_USER,
                    "--password", GITEA_ADMIN_PASSWORD,
                    "--email", "admin@test.local",
                    "--admin");
            if (result.getExitCode() != 0) {
                throw new IllegalStateException("Gitea admin creation failed: " + result.getStderr());
            }

            adminToken = createApiToken(giteaBaseUrl);
            String repoName = "gitops-proxy-repo";
            createRepo(giteaBaseUrl, repoName);
            pushFile(giteaBaseUrl, repoName, "npm.yaml", """
                    rules:
                      - package: "lodash"
                        version: "*"
                        action: "BLACKLIST"
                        reason: "Corporate policy (via proxy integration test)"
                    """);

            // URL uses the Docker network alias "gitea" so that JGit routes
            // through Squid, which can resolve the alias within the shared network.
            gitopsRepoUrl = "http://gitea:3000/" + GITEA_ADMIN_USER + "/" + repoName + ".git";
        } catch (Exception e) {
            throw new RuntimeException("Gitea setup failed", e);
        }
    }

    private static String createApiToken(String giteaBaseUrl) throws Exception {
        String body = "{\"name\":\"ci-proxy-test-token\",\"scopes\":[\"read:repository\"]}";
        HttpResponse<String> response = giteaPost(giteaBaseUrl, "/api/v1/users/" + GITEA_ADMIN_USER + "/tokens", body);
        JsonNode json = JSON.readTree(response.body());
        return json.get("sha1").asText();
    }

    private static void createRepo(String giteaBaseUrl, String repoName) throws Exception {
        String body = "{\"name\":\"" + repoName + "\",\"private\":false,"
                + "\"auto_init\":true,\"default_branch\":\"main\"}";
        giteaPost(giteaBaseUrl, "/api/v1/user/repos", body);
    }

    private static void pushFile(String giteaBaseUrl, String repoName, String filename, String content)
            throws Exception {
        String encoded = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
        String body = "{\"message\":\"Add " + filename + "\",\"content\":\"" + encoded + "\"}";
        giteaPost(giteaBaseUrl, "/api/v1/repos/" + GITEA_ADMIN_USER + "/" + repoName + "/contents/" + filename, body);
    }

    private static HttpResponse<String> giteaPost(String giteaBaseUrl, String path, String body) throws Exception {
        String credentials = GITEA_ADMIN_USER + ":" + GITEA_ADMIN_PASSWORD;
        String auth = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create(giteaBaseUrl + path))
                        .header("Authorization", auth)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String minimalOsvJson(String id, String pkgName, String ecosystem, String version) {
        return """
                {
                  "id": "%s",
                  "summary": "Test advisory for %s",
                  "published": "2024-01-01T00:00:00Z",
                  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                  "affected": [{
                    "package": {"name": "%s", "ecosystem": "%s"},
                    "versions": ["%s"]
                  }]
                }
                """.formatted(id, pkgName, pkgName, ecosystem, version);
    }

    private static void deleteDirectory(Path dir) throws Exception {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> stream = Files.walk(dir)) {
            stream.sorted(java.util.Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    });
        }
        Files.createDirectories(dir);
    }
}
