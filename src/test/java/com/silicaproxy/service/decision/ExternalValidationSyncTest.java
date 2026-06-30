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
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
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
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// External validation — sync mode, fail-open=true, blocking=true (default secure configuration).
// Quarantine, deprecation, and OSV are disabled so tests isolate external validation behaviour.
class ExternalValidationSyncTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private ExternalValidationVerdictsDao verdictsDao;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.trigger-async-on-sync-block", () -> "false");
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.test-scanner.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.http-client.external-validation-read-timeout-seconds", () -> "1");
        registry.add("silicaproxy.quarantine.enabled", () -> "false");
        registry.add("silicaproxy.deprecation.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
    }

    @BeforeEach
    void setUp() throws Exception {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES ('lodash', 'npm', '4.17.21', NOW() - INTERVAL '365 days')
                """).update();
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

    // Test 15 — sync_allowed_requestForwarded
    @Test
    void sync_allowed_requestIsForwarded() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\",\"reason\":\"No issues found\"}")));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 16 — sync_blocked_returns403WithReason
    @Test
    void sync_blocked_returns403WithReasonInBody() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Malicious package\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("Malicious package");
        }
    }

    // Test 18 — sync_timeout_failOpen_requestForwarded
    @Test
    void sync_timeout_failOpen_requestIsForwarded() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withFixedDelay(3000).withStatus(200)));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // Test 20 — sync_networkFault_failOpen_requestForwarded
    @Test
    void sync_networkFault_failOpen_requestIsForwarded() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse()
                        .withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER)));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // A malformed/unexpected verdict must still honor fail-open (request forwarded here,
    // since this test class is configured fail-open=true) instead of being silently ALLOWED
    // as if the verdict had been "ALLOWED" — see sync_malformedVerdict_failClosed_returns403
    // in ExternalValidationSyncFailClosedTest for the fail-closed counterpart.
    @Test
    void sync_malformedVerdict_failOpen_requestIsForwarded() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"UNKNOWN\"}")));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Recorded as TIMEOUT, not cached as a real ALLOWED verdict
        var cached = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(cached).isPresent();
        assertThat(cached.get().status()).isEqualTo("TIMEOUT");
    }

    // Test 39 — sync_http500_failOpen_requestForwarded
    @Test
    void sync_http500_failOpen_requestIsForwarded() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(500)));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // Test 21 — sync_secondRequest_usesCache_noExtraCall
    @Test
    void sync_secondRequest_usesCache() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        // External service called exactly once — second request used the cache
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 33 — sync_cacheExpired_callsServiceAgain
    @Test
    void sync_cacheExpired_callsServiceAgainOnNextRequest() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        // Pre-populate cache with expired ALLOWED entry
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('test-scanner', 'lodash', 'npm', '4.17.21', 'SYNC', 'ALLOWED', ?)
                """).param(Timestamp.from(Instant.now().minus(1, ChronoUnit.MINUTES))).update();

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        // Cache was expired, so external service is called again
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 22 — sync_blocked_verdictStoredPermanentlyInVerdictsTable
    @Test
    void sync_blocked_verdictStoredPermanentlyInVerdictsTable() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Malware found\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException ignored) {}

        var verdict = verdictsDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(verdict).isPresent();
        assertThat(verdict.get().reason()).isEqualTo("Malware found");
    }

    // Test 22b — sync_allowed_verdictStoredInCacheWithTtl
    @Test
    void sync_allowed_verdictStoredInCacheWithTtl() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\",\"reason\":\"Clean\"}")));

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        var cached = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(cached).isPresent();
        assertThat(cached.get().status()).isEqualTo("ALLOWED");
        assertThat(cached.get().mode()).isEqualTo("SYNC");
        assertThat(cached.get().callbackToken()).isNull();
        assertThat(cached.get().expiresAt()).isAfter(Instant.now().plus(59, ChronoUnit.MINUTES));
    }

    // Test 22c — sync_blockedFromCache_usesVerdictsTable
    @Test
    void sync_blockedFromVerdictsCache_returns403WithoutCallingService() {
        // Pre-populate verdicts table (permanent BLOCK)
        verdictsDao.save("test-scanner", "lodash", "npm", "4.17.21", "Previously blocked");

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        // External service NOT called — verdict came from permanent cache
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 37 — sync_blocked_auditLogContainsExternalValidationSource
    @Test
    void sync_blocked_auditLogContainsExternalValidationSource() throws InterruptedException {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Test block\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException ignored) {}

        Thread.sleep(300);  // Allow async audit flush

        var auditRows = jdbcClient.sql("""
                SELECT decision_source, verdict FROM proxy_audit_logs
                WHERE package_name = 'lodash' ORDER BY timestamp DESC LIMIT 1
                """).query().listOfRows();
        assertThat(auditRows).isNotEmpty();
        assertThat(auditRows.get(0).get("decision_source")).isEqualTo("EXTERNAL_VALIDATION");
        assertThat(auditRows.get(0).get("verdict")).isEqualTo("BLOCK");
    }

    // Test 64 — sync_withApiKey_sendsAuthorizationHeader
    // (Tested in ExternalValidationSyncApiKeyTest — separate Spring context with api-key configured)

    // Verify POST body contains correct package fields
    @Test
    void sync_postBodyContainsPackageFields() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        wireMock.verify(postRequestedFor(urlEqualTo("/external-validate"))
                .withRequestBody(matchingJsonPath("$.packageName", equalTo("lodash")))
                .withRequestBody(matchingJsonPath("$.version", equalTo("4.17.21")))
                .withRequestBody(matchingJsonPath("$.ecosystem", equalTo("npm"))));
    }
}
