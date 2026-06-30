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


package com.silicaproxy.service.decision;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.client.ProxyStreamClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// Verifies the position of external validation in the decision chain:
//   company_policy → local_vuln → api_cache → quarantine → deprecation
//   → EXTERNAL VALIDATION → osv/deps.dev
// Steps before external validation short-circuit it; steps after it are skipped when
// external validation returns a definitive verdict.
class ExternalValidationChainPositionTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.test-scanner.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.http-client.external-validation-read-timeout-seconds", () -> "1");
        // Quarantine and deprecation enabled so we can test they bypass external validation
        registry.add("silicaproxy.quarantine.enabled", () -> "true");
        registry.add("silicaproxy.quarantine.ecosystems.npm.enabled", () -> "true");
        registry.add("silicaproxy.quarantine.ecosystems.npm.min-age-days", () -> "7");
        registry.add("silicaproxy.deprecation.enabled", () -> "true");
        registry.add("silicaproxy.deprecation.ecosystems.npm", () -> "true");
        // OSV enabled to verify it's skipped when external validation returns verdict
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "true");
    }

    @BeforeEach
    void setUp() throws Exception {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        proxyRestClient = RestClient.builder().requestFactory(factory).build();

        when(proxyStreamClient.streamContent(any(), any()))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream("fake-content".getBytes())));
    }

    // Test 27 — companyBlacklist_bypassesExternalService
    @Test
    void companyBlacklist_blocksBeforeExternalValidation() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '*', 'BLACKLIST', 'Forbidden', 'security')
                """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        // External validation was NOT called (blacklist short-circuited the chain)
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 59 — companyWhitelist_bypassesExternalService
    @Test
    void companyWhitelist_allowsBeforeExternalValidation() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '*', 'WHITELIST', 'Approved', 'security')
                """).update();

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 60 — localVulnerability_bypassesExternalService
    @Test
    void localVulnerability_blocksBeforeExternalValidation() {
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities
                    (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-2023-001', 'OSV', 'lodash', 'npm', 'Critical bug',
                        '[\"4.17.21\"]'::jsonb, 9.8)
                """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 61 — apiCacheHit_bypassesExternalService
    @Test
    void apiCacheHit_allowsBeforeExternalValidation() {
        jdbcClient.sql("""
                INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
                VALUES ('lodash', 'npm', '4.17.21', true, 'osv',
                        NOW() + INTERVAL '1 hour')
                """).update();

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 28 — quarantine_bypassesExternalService (young package blocked by quarantine)
    @Test
    void quarantine_blocksBeforeExternalValidation() {
        // NPM registry returns a very recently published package (1 day old < 7 day threshold)
        String recentDate = Instant.now().minusSeconds(86400).toString();
        wireMock.stubFor(get(urlEqualTo("/lodash"))
                .willReturn(okJson("{" +
                        "\"time\":{\"4.17.21\":\"" + recentDate + "\"}," +
                        "\"versions\":{\"4.17.21\":{\"name\":\"lodash\",\"version\":\"4.17.21\"}}}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 29 — externalBlocks_osvNeverCalled
    @Test
    void externalValidationBlocks_osvIsNeverCalled() {
        // Package is old enough (no quarantine issue)
        String oldDate = Instant.now().minusSeconds(86400 * 30).toString();
        wireMock.stubFor(get(urlEqualTo("/lodash"))
                .willReturn(okJson("{" +
                        "\"time\":{\"4.17.21\":\"" + oldDate + "\"}," +
                        "\"versions\":{\"4.17.21\":{\"name\":\"lodash\",\"version\":\"4.17.21\"}}}")));

        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Deep scan: malware\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException ignored) {}

        // OSV was never called (external validation returned BLOCK before reaching OSV)
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/v1/query")));
    }

    // Test 62 — externalAllows_osvNotCalled
    @Test
    void externalValidationAllows_osvIsNotCalled() {
        String oldDate = Instant.now().minusSeconds(86400 * 30).toString();
        wireMock.stubFor(get(urlEqualTo("/lodash"))
                .willReturn(okJson("{" +
                        "\"time\":{\"4.17.21\":\"" + oldDate + "\"}," +
                        "\"versions\":{\"4.17.21\":{\"name\":\"lodash\",\"version\":\"4.17.21\"}}}")));

        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\",\"reason\":\"Clean\"}")));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        // External validation returned ALLOWED — OSV is not needed
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/v1/query")));
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }
}
