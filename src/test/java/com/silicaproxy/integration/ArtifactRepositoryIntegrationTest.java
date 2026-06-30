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


package com.silicaproxy.integration;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.service.interception.LoomProxyServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@Tag("artifact-repository")
class ArtifactRepositoryIntegrationTest extends BaseIntegrationTest {

    private static final Network network = Network.newNetwork();

    private static final PostgreSQLContainer<?> postgresContainer =
            new PostgreSQLContainer<>("postgres:18-alpine")
                    .withNetwork(network)
                    .withNetworkAliases("artifactory-db")
                    .withDatabaseName("artifactory_db")
                    .withUsername("postgres")
                    .withPassword("password");

    private static final GenericContainer<?> repositoryContainer =
            new GenericContainer<>(DockerImageName.parse("releases-docker.jfrog.io/jfrog/artifactory-oss:latest"))
                    .withNetwork(network)
                    .withExposedPorts(8081, 8082)
                    .withEnv("JF_SHARED_SECURITY_MASTERKEY", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .withEnv("JF_SHARED_SECURITY_JOINKEY", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .withEnv("JF_DATABASE_TYPE", "postgresql")
                    .withEnv("JF_DATABASE_URL", "jdbc:postgresql://artifactory-db:5432/artifactory_db")
                    .withEnv("JF_DATABASE_USER", "postgres")
                    .withEnv("JF_DATABASE_PASSWORD", "password")
                    .withEnv("JF_JFCONNECT_ENABLED", "false")
                    .waitingFor(Wait.forHttp("/artifactory/api/system/ping")
                            .forPort(8082)
                            .withStartupTimeout(Duration.ofMinutes(5)));

    static {
        postgresContainer.start();
        repositoryContainer.start();
    }

    @Autowired
    private LoomProxyServer loomProxyServer;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @LocalServerPort
    private int randomServerPort;

    private boolean configured = false;

    @BeforeEach
    void setUp() throws Exception {
        jdbcClient.sql("DELETE FROM company_policies").update();
        jdbcClient.sql("DELETE FROM public_vulnerabilities").update();
        jdbcClient.sql("DELETE FROM api_cache").update();
        jdbcClient.sql("DELETE FROM package_metadata").update();
        wireMock.resetAll();

        if (!configured) {
            int repositoryPort = repositoryContainer.getMappedPort(8082);
            String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;
            configureArtifactRepository(repositoryUrl, loomProxyServer.getProxyPort());
            configured = true;
        }
    }

    private void configureArtifactRepository(String repositoryUrl, int proxyPort) throws Exception {
        String configTemplate;
        try (InputStream is = ArtifactRepositoryIntegrationTest.class.getClassLoader()
                .getResourceAsStream("fixtures/artifactory.config.xml")) {
            if (is == null) {
                throw new IllegalStateException("Missing fixtures/artifactory.config.xml in classpath");
            }
            configTemplate = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }

        String updatedConfig = configTemplate.replace("<port>8080</port>", "<port>" + proxyPort + "</port>");

        HttpClient client = HttpClient.newHttpClient();
        String authHeader = "Basic " + java.util.Base64.getEncoder().encodeToString("admin:password".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/api/system/configuration"))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/xml")
                .POST(HttpRequest.BodyPublishers.ofString(updatedConfig))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            System.err.println("Warning: Failed to configure artifact repository: " + response.statusCode() + " " + response.body());
        } else {
            System.out.println("Artifact repository configured to use proxy port " + proxyPort);
        }
    }

    @Test
    void testArtifactRepositoryPing() throws Exception {
        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/api/system/ping"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("OK");
    }

    @Test
    void shouldAllowMavenPackageViaArtifactRepository() throws Exception {
        wireMock.stubFor(head(urlEqualTo("/maven2/org/slf4j/slf4j-api/2.0.9/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", "Wed, 16 Nov 2022 13:00:00 GMT")));

        byte[] jarContent = "fake-maven-jar-bytes".getBytes();
        when(proxyStreamClient.streamContent(eq("https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar"), any(org.springframework.http.HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new org.springframework.http.HttpHeaders(),
                        new java.io.ByteArrayInputStream(jarContent)
                ));

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/MavenCentral/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar"))
                .GET()
                .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(jarContent);
    }

    @Test
    void shouldBlockMavenPackageViaArtifactRepository() throws Exception {
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('org.slf4j:slf4j-api', 'maven', '*', 'BLACKLIST', 'Forbidden by security', 'admin', NOW())
        """).update();

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/MavenCentral/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(200);
    }

    @Test
    void shouldAllowNpmPackageViaArtifactRepository() throws Exception {
        wireMock.stubFor(get(urlEqualTo("/lodash"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "time": {
                                "4.17.21": "2021-05-02T12:00:00.000Z"
                              }
                            }
                            """)));

        byte[] tarballContent = "fake-npm-tgz-bytes".getBytes();
        when(proxyStreamClient.streamContent(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"), any(org.springframework.http.HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new org.springframework.http.HttpHeaders(),
                        new java.io.ByteArrayInputStream(tarballContent)
                ));

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/npm-remote/lodash/-/lodash-4.17.21.tgz"))
                .GET()
                .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(tarballContent);
    }

    @Test
    void shouldBlockNpmPackageViaArtifactRepository() throws Exception {
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('lodash', 'npm', '*', 'BLACKLIST', 'NPM Package banned', 'admin', NOW())
        """).update();

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/npm-remote/lodash/-/lodash-4.17.21.tgz"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(200);
    }

    @Test
    void shouldBlockMavenPackageWhenHighCvssViaArtifactRepository() throws Exception {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('GHSA-2382-qx5h-rvqh', 'OSV', 'org.odata4j:odata4j-core', 'maven',
                    'Critical odata4j vulnerability', 'Details', '["0.7.0"]'::jsonb, 9.8, NOW())
        """).update();

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/MavenCentral/org/odata4j/odata4j-core/0.7.0/odata4j-core-0.7.0.jar"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(200);
    }

    @Test
    void shouldBlockMavenPackageWhenMaliciousViaArtifactRepository() throws Exception {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('MAL-2025-191470', 'OSV', 'org.mvnpm:posthog-node', 'maven',
                    'Malicious Maven Package', 'Details', '["4.18.1"]'::jsonb, 0.0, NOW())
        """).update();

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/MavenCentral/org/mvnpm/posthog-node/4.18.1/posthog-node-4.18.1.jar"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(200);
    }

    @Test
    void shouldBlockNpmPackageWhenHighCvssViaArtifactRepository() throws Exception {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('GHSA-9qgm-w87q-hx89', 'OSV', 'strapi', 'npm',
                    'High CVSS Npm vulnerability', 'Details', '["3.0.0"]'::jsonb, 9.8, NOW())
        """).update();

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/npm-remote/strapi/-/strapi-3.0.0.tgz"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(200);
    }

    @Test
    void shouldBlockNpmPackageWhenMaliciousViaArtifactRepository() throws Exception {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('MAL-2025-33910', 'OSV', 'standardwebappwebweb', 'npm',
                    'Malicious Npm Package', 'Details', '["1.0.0"]'::jsonb, 0.0, NOW())
        """).update();

        int repositoryPort = repositoryContainer.getMappedPort(8082);
        String repositoryUrl = "http://" + repositoryContainer.getHost() + ":" + repositoryPort;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(repositoryUrl + "/artifactory/npm-remote/standardwebappwebweb/-/standardwebappwebweb-1.0.0.tgz"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isNotEqualTo(200);
    }
}
