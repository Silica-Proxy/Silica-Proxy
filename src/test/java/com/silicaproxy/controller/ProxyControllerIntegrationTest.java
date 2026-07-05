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


package com.silicaproxy.controller;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.UrlParserService;
import io.micrometer.core.instrument.MeterRegistry;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@TestPropertySource(properties = "silicaproxy.quarantine.ecosystems.npm.enabled=true")
class ProxyControllerIntegrationTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @Mock
    private SecurityService securityService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private UrlParserService urlParserService;

    @Autowired
    private MeterRegistry meterRegistry;

    @Autowired
    private ObjectMapper objectMapper;

    private RestClient proxyRestClient;

    @BeforeEach
    void setUp() {
        jdbcClient.sql("DELETE FROM company_policies").update();
        jdbcClient.sql("DELETE FROM public_vulnerabilities").update();
        jdbcClient.sql("DELETE FROM api_cache").update();
        jdbcClient.sql("DELETE FROM package_metadata").update();
        wireMock.resetAll();

        // Create a RestClient that routes requests through our locally running proxy server
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        this.proxyRestClient = RestClient.builder().requestFactory(factory).build();
    }

    @Test
    void shouldAllowAndProxyMavenPackage() throws Exception {
        wireMock.stubFor(head(urlEqualTo("/maven2/org/slf4j/slf4j-api/2.0.9/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", "Wed, 16 Nov 2022 13:00:00 GMT")));

        byte[] jarContent = "fake-maven-jar-bytes".getBytes();
        when(proxyStreamClient.streamContent(any(String.class), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(jarContent)
                ));

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(jarContent);
    }

    @Test
    void shouldBlockMavenPackageWhenBlacklisted() {
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('org.slf4j:slf4j-api', 'maven', '%', 'BLACKLIST', 'Forbidden by security', 'admin', NOW())
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"error\":\"SecurityBlocked\"")
                    .contains("\"package\":\"org.slf4j:slf4j-api\"")
                    .contains("\"version\":\"2.0.9\"")
                    .contains("\"ecosystem\":\"maven\"")
                    .contains("\"detail\":\"Forbidden by security\"");
        }
    }

    @Test
    void shouldAllowAndProxyNpmPackage() throws Exception {
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
        when(proxyStreamClient.streamContent(any(String.class), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(tarballContent)
                ));

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(tarballContent);
    }

    @Test
    void shouldBlockNpmPackageWhenBlacklisted() {
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('lodash', 'npm', '%', 'BLACKLIST', 'NPM Package banned', 'admin', NOW())
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"error\":\"SecurityBlocked\"")
                    .contains("\"package\":\"lodash\"")
                    .contains("\"version\":\"4.17.21\"")
                    .contains("\"ecosystem\":\"npm\"")
                    .contains("\"detail\":\"NPM Package banned\"");
        }
    }

    @Test
    void shouldBypassSecurityCheckForUnknownPackages() throws Exception {
        byte[] fakeContent = "system-version-info".getBytes();
        when(proxyStreamClient.streamContent(any(String.class), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeContent)
                ));

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://repo1.maven.org/api/system/version")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(fakeContent);
    }

    @Test
    void shouldBlockMavenPackageWhenHighCvss() {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('GHSA-2382-qx5h-rvqh', 'OSV', 'org.odata4j:odata4j-core', 'maven',
                    'Critical odata4j vulnerability', 'Details', '["0.7.0"]'::jsonb, 9.8, NOW())
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://repo1.maven.org/maven2/org/odata4j/odata4j-core/0.7.0/odata4j-core-0.7.0.jar")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"error\":\"SecurityBlocked\"")
                    .contains("\"step\":\"PUBLIC_VULN\"")
                    .contains("\"package\":\"org.odata4j:odata4j-core\"")
                    .contains("\"version\":\"0.7.0\"")
                    .contains("\"ecosystem\":\"maven\"")
                    .contains("\"detail\":\"Critical odata4j vulnerability\"");
        }
    }

    @Test
    void shouldBlockMavenPackageWhenMalicious() {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('MAL-2025-191470', 'OSV', 'org.mvnpm:posthog-node', 'maven',
                    'Malicious Maven Package', 'Details', '["4.18.1"]'::jsonb, 0.0, NOW())
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://repo1.maven.org/maven2/org/mvnpm/posthog-node/4.18.1/posthog-node-4.18.1.jar")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"error\":\"SecurityBlocked\"")
                    .contains("\"step\":\"PUBLIC_VULN_MALWARE\"")
                    .contains("\"package\":\"org.mvnpm:posthog-node\"")
                    .contains("\"version\":\"4.18.1\"")
                    .contains("\"ecosystem\":\"maven\"")
                    .contains("\"detail\":\"Malicious Maven Package\"");
        }
    }

    @Test
    void shouldBlockNpmPackageWhenHighCvss() {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('GHSA-9qgm-w87q-hx89', 'OSV', 'strapi', 'npm',
                    'High CVSS Npm vulnerability', 'Details', '["3.0.0"]'::jsonb, 9.8, NOW())
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/strapi/-/strapi-3.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"error\":\"SecurityBlocked\"")
                    .contains("\"step\":\"PUBLIC_VULN\"")
                    .contains("\"package\":\"strapi\"")
                    .contains("\"version\":\"3.0.0\"")
                    .contains("\"ecosystem\":\"npm\"")
                    .contains("\"detail\":\"High CVSS Npm vulnerability\"");
        }
    }

    @Test
    void shouldBlockNpmPackageWhenMalicious() {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at)
            VALUES ('MAL-2025-33910', 'OSV', 'standardwebappwebweb', 'npm',
                    'Malicious Npm Package', 'Details', '["1.0.0"]'::jsonb, 0.0, NOW())
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/standardwebappwebweb/-/standardwebappwebweb-1.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"error\":\"SecurityBlocked\"")
                    .contains("\"step\":\"PUBLIC_VULN_MALWARE\"")
                    .contains("\"package\":\"standardwebappwebweb\"")
                    .contains("\"version\":\"1.0.0\"")
                    .contains("\"ecosystem\":\"npm\"")
                    .contains("\"detail\":\"Malicious Npm Package\"");
        }
    }

    private void stubStreaming(byte[] content) throws Exception {
        when(proxyStreamClient.streamContent(any(String.class), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(content)
                ));
    }

    // Wait for async (Loom) writing of an audit log row, up to 2.5s (50 x 50ms), as in
    // AuditLogServiceTest.
    private List<Map<String, Object>> awaitAuditLogRow(String packageName) throws InterruptedException {
        for (int attempts = 0; attempts < 50; attempts++) {
            List<Map<String, Object>> logs = jdbcClient.sql(
                    "SELECT * FROM proxy_audit_logs WHERE package_name = ?").params(packageName).query().listOfRows();
            if (!logs.isEmpty()) {
                return logs;
            }
            Thread.sleep(50);
        }
        return List.of();
    }

    @Test
    void shouldAllowWhitelistedPackageEvenWithCriticalVulnerability() throws Exception {
        // Priority 1 (company_policies) must win over priority 2 (public_vulnerabilities)
        // in the single SQL query of DecisionDao, even facing a known critical vulnerability.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('vuln-allowed-pkg', 'npm', '%', 'WHITELIST', 'Approved security exception', 'security', NOW())
        """).update();
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
            VALUES ('CVE-CRITICAL', 'OSV', 'vuln-allowed-pkg', 'npm', 'Critical bug', '["1.0.0"]'::jsonb, 9.8)
        """).update();
        stubStreaming("ok".getBytes());

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/vuln-allowed-pkg/-/vuln-allowed-pkg-1.0.0.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        List<Map<String, Object>> logs = awaitAuditLogRow("vuln-allowed-pkg");
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).get("decision_source")).isEqualTo("COMPANY_POLICY");
        assertThat(logs.get(0).get("verdict")).isEqualTo("WHITELIST");
    }

    @Test
    void shouldAllowFromApiCacheWithoutCallingRegistryOrOsv() throws Exception {
        // No WireMock stub npm/OSV : if the cache did not short-circuit the evaluation, the
        // registry would return 404 (not stubbed) and the proxy would fall back to fail-open (REGISTRY_ERROR),
        // not to ALLOW via API_CACHE.
        jdbcClient.sql("""
            INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
            VALUES ('cached-safe-pkg', 'npm', '1.0.0', true, 'OSV_LIVE', NOW() + INTERVAL '1 day')
        """).update();
        stubStreaming("ok".getBytes());

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/cached-safe-pkg/-/cached-safe-pkg-1.0.0.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(0, getRequestedFor(urlEqualTo("/cached-safe-pkg")));

        List<Map<String, Object>> logs = awaitAuditLogRow("cached-safe-pkg");
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).get("decision_source")).isEqualTo("API_CACHE");
        assertThat(logs.get(0).get("verdict")).isEqualTo("ALLOW");
    }

    @Test
    void shouldBlockFromApiCacheWithoutCallingRegistryOrOsv() throws Exception {
        jdbcClient.sql("""
            INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
            VALUES ('cached-vuln-pkg', 'npm', '1.0.0', false, 'OSV_LIVE', NOW() + INTERVAL '1 day')
        """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/cached-vuln-pkg/-/cached-vuln-pkg-1.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            assertThat(e.getResponseBodyAsString()).contains("\"step\":\"API_CACHE\"");
        }

        verifyNoInteractions(proxyStreamClient);
        wireMock.verify(0, getRequestedFor(urlEqualTo("/cached-vuln-pkg")));
    }

    @Test
    void shouldIgnoreExpiredApiCacheEntryAndReEvaluateViaOsv() throws Exception {
        jdbcClient.sql("""
            INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
            VALUES ('expired-cache-pkg', 'npm', '1.0.0', false, 'OSV_LIVE', NOW() - INTERVAL '1 day')
        """).update();

        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/expired-cache-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"1.0.0\": \"" + publishedAt + "\"}, \"versions\": {\"1.0.0\": {}}}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody("{}")));
        stubStreaming("ok".getBytes());

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/expired-cache-pkg/-/expired-cache-pkg-1.0.0.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(1, getRequestedFor(urlEqualTo("/expired-cache-pkg")));

        List<Map<String, Object>> logs = awaitAuditLogRow("expired-cache-pkg");
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).get("decision_source")).isEqualTo("OSV_LIVE");
    }

    @Test
    void shouldBlockViaQuarantineAndNotPersistApiCacheEntry() throws Exception {
        Instant publishedAt = Instant.now().minus(2, ChronoUnit.DAYS); // < 7 days (default npm threshold)
        wireMock.stubFor(get(urlEqualTo("/brand-new-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"1.0.0\": \"" + publishedAt + "\"}, \"versions\": {\"1.0.0\": {}}}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/brand-new-pkg/-/brand-new-pkg-1.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            assertThat(e.getResponseBodyAsString()).contains("\"step\":\"REGISTRY_QUARANTINE\"");
        }

        Long cacheCount = jdbcClient.sql(
                "SELECT count(*) FROM api_cache WHERE package_name = 'brand-new-pkg'").query(Long.class).single();
        assertThat(cacheCount).isZero();

        Long metadataCount = jdbcClient.sql(
                "SELECT count(*) FROM package_metadata WHERE package_name = 'brand-new-pkg'").query(Long.class).single();
        assertThat(metadataCount).isEqualTo(1L);
    }

    @Test
    void shouldBlockViaDeprecationAndPersistPermanentApiCacheEntry() throws Exception {
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/old-deprecated-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "\"time\": {\"1.0.0\": \"" + publishedAt + "\"}," +
                                "\"versions\": {\"1.0.0\": {\"deprecated\": \"Use other-pkg instead\"}}" +
                                "}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/old-deprecated-pkg/-/old-deprecated-pkg-1.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            assertThat(e.getResponseBodyAsString()).contains("\"step\":\"REGISTRY_DEPRECATION\"");
        }

        Map<String, Object> cacheRow = jdbcClient.sql(
                "SELECT * FROM api_cache WHERE package_name = 'old-deprecated-pkg'").query().singleRow();
        assertThat(cacheRow.get("is_secure")).isEqualTo(false);
        assertThat(((java.sql.Timestamp) cacheRow.get("expires_at")).toInstant())
                .isAfter(Instant.now().plus(365, ChronoUnit.DAYS));
    }

    @Test
    void shouldResolveRegistryAndOsvOnlyOnceAcrossTwoRequestsForSamePackage() throws Exception {
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/reuse-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"1.0.0\": \"" + publishedAt + "\"}, \"versions\": {\"1.0.0\": {}}}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody("{}")));
        stubStreaming("ok".getBytes());

        for (int i = 0; i < 2; i++) {
            ResponseEntity<byte[]> response = proxyRestClient.get()
                    .uri("http://registry.npmjs.org/reuse-pkg/-/reuse-pkg-1.0.0.tgz")
                    .retrieve()
                    .toEntity(byte[].class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        // The 2nd call must be resolved via package_metadata (local) + api_cache (local) : no
        // additional network call to npm registry or to OSV fallback API.
        wireMock.verify(1, getRequestedFor(urlEqualTo("/reuse-pkg")));
        wireMock.verify(1, postRequestedFor(urlEqualTo("/v1/query")));
    }

    @Test
    void shouldAllowMavenPackageWhenCvssBelowEcosystemThreshold() throws Exception {
        // Default Maven threshold : max-allowed-cvss = 7.0. A vulnerability with 3.0 must be filtered by
        // SQL (cvss_score >= minCvss) and must therefore not block the package.
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
            VALUES ('CVE-LOW', 'OSV', 'com.example:low-severity-lib', 'maven', 'Minor issue', '["1.0.0"]'::jsonb, 3.0)
        """).update();

        wireMock.stubFor(head(urlEqualTo("/maven2/com/example/low-severity-lib/1.0.0/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", "Wed, 16 Nov 2022 13:00:00 GMT")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody("{}")));
        stubStreaming("jar-bytes".getBytes());

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://repo1.maven.org/maven2/com/example/low-severity-lib/1.0.0/low-severity-lib-1.0.0.jar")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void shouldPersistAuditLogRowThroughFullControllerServiceDaoChain() throws Exception {
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('audited-pkg', 'npm', '%', 'WHITELIST', 'Test audit', 'security', NOW())
        """).update();
        stubStreaming("ok".getBytes());

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/audited-pkg/-/audited-pkg-1.0.0.tgz")
                .retrieve()
                .toEntity(byte[].class);

        List<Map<String, Object>> logs = awaitAuditLogRow("audited-pkg");
        assertThat(logs).hasSize(1);
        Map<String, Object> log = logs.get(0);
        assertThat(log.get("package_version")).isEqualTo("1.0.0");
        assertThat(log.get("ecosystem")).isEqualTo("npm");
        assertThat(log.get("decision_source")).isEqualTo("COMPANY_POLICY");
        assertThat(log.get("verdict")).isEqualTo("WHITELIST");
        assertThat((Integer) log.get("execution_time_ms")).isGreaterThanOrEqualTo(0);
    }

    @Test
    void shouldAllowThenBlockAfterAddingBlacklistPolicy() throws Exception {
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/dynamic-allow-then-block-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"1.0.0\": \"" + publishedAt + "\"}, \"versions\": {\"1.0.0\": {}}}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody("{}")));
        stubStreaming("ok".getBytes());

        // 1. Absent from all tables (company_policies, public_vulnerabilities, api_cache) :
        // allowed by default via OSV fallback chain.
        ResponseEntity<byte[]> firstResponse = proxyRestClient.get()
                .uri("http://registry.npmjs.org/dynamic-allow-then-block-pkg/-/dynamic-allow-then-block-pkg-1.0.0.tgz")
                .retrieve()
                .toEntity(byte[].class);
        assertThat(firstResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 2. Corporate governance manually blacklists the package afterwards.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('dynamic-allow-then-block-pkg', 'npm', '%', 'BLACKLIST', 'Blacklist after security review', 'security', NOW())
        """).update();

        // 3. Same package/version : now blocked. The corporate policy (priority 1)
        // wins over the ALLOW verdict already present in cache (priority 3, from the previous call).
        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/dynamic-allow-then-block-pkg/-/dynamic-allow-then-block-pkg-1.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden after blacklisting");
        } catch (HttpClientErrorException.Forbidden e) {
            assertThat(e.getResponseBodyAsString())
                    .contains("\"step\":\"COMPANY_POLICY\"")
                    .contains("\"detail\":\"Blacklist after security review\"");
        }
    }

    @Test
    void shouldBlockThenAllowAfterAddingWhitelistPolicy() throws Exception {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
            VALUES ('CVE-DYNAMIC', 'OSV', 'dynamic-block-then-allow-pkg', 'npm', 'Critical bug', '["1.0.0"]'::jsonb, 9.8)
        """).update();

        // 1. Known critical public vulnerability : blocked.
        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/dynamic-block-then-allow-pkg/-/dynamic-block-then-allow-pkg-1.0.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            assertThat(e.getResponseBodyAsString()).contains("\"step\":\"PUBLIC_VULN\"");
        }

        // 2. An exception is manually approved by security despite the CVE.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
            VALUES ('dynamic-block-then-allow-pkg', 'npm', '%', 'WHITELIST', 'Exception approved despite CVE', 'security', NOW())
        """).update();
        stubStreaming("ok".getBytes());

        // 3. Same package/version : now allowed. The corporate policy (priority 1)
        // wins over the known public vulnerability (priority 2).
        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/dynamic-block-then-allow-pkg/-/dynamic-block-then-allow-pkg-1.0.0.tgz")
                .retrieve()
                .toEntity(byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void shouldRejectNonHttpUrl() throws Exception {
        // Non-HTTP URLs (ftp, file, etc.) must be rejected with HTTP 400
        // (spec §6.1, ProxyController L84-85).
        // Since we cannot easily send an ftp:// request via HTTP, we create a mock
        // of HttpServletRequest with a RequestURL starting with ftp://
        
        // Create a mock of HttpServletRequest
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        
        // Simulate an ftp URL
        StringBuffer ftpUrl = new StringBuffer("ftp://example.com/package.tar.gz");
        when(mockRequest.getRequestURL()).thenReturn(ftpUrl);
        when(mockRequest.getQueryString()).thenReturn(null);
        when(mockRequest.getMethod()).thenReturn("GET");
        when(mockRequest.getRequestURI()).thenReturn("/ftp://example.com/package.tar.gz");
        
        // Create the controller
        ProxyController controller = new ProxyController(securityService, auditLogService, proxyStreamClient, urlParserService, meterRegistry, objectMapper);
        
        // Call the method directly
        controller.proxyRequest(mockRequest, mockResponse);
        
        // Verify that sendError was called with SC_BAD_REQUEST
        verify(mockResponse).sendError(HttpServletResponse.SC_BAD_REQUEST, "Only absolute HTTP/HTTPS requests are supported by this proxy.");
    }
}
