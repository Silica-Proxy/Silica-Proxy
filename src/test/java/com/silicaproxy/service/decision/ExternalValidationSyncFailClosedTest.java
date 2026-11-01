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

import com.silicaproxy.config.Metrics;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.client.ProxyStreamClient;
import io.micrometer.core.instrument.MeterRegistry;
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
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// External validation — sync mode, fail-open=false (fail-closed).
// When the external service is unreachable, times out or answers no usable verdict, the package
// is blocked temporarily : 429 + Retry-After + no-store, source EXTERNAL_VALIDATION_UNAVAILABLE.
class ExternalValidationSyncFailClosedTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @Autowired
    private MeterRegistry meterRegistry;

    private RestClient proxyRestClient;

    private double unavailableBlockCount() {
        io.micrometer.core.instrument.Counter counter = meterRegistry
                .find(Metrics.BLOCK_REASON_METRIC)
                .tag(Metrics.TAG_REASON, Metrics.REASON_UNAVAILABLE)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.test-scanner.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "false");
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

    // Test 19 — sync_timeout_failClosed_returns429Unavailable
    @Test
    void sync_timeout_failClosed_returns429Unavailable() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withFixedDelay(3000).withStatus(200)));

        double before = unavailableBlockCount();
        assertUnavailable(requestBlocked());
        // Blocked only because the service timed out (fail-closed), not a real malicious verdict.
        assertThat(unavailableBlockCount() - before).isEqualTo(1.0);
    }

    // Test 38 — sync_networkFault_failClosed_returns429Unavailable
    @Test
    void sync_networkFault_failClosed_returns429Unavailable() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse()
                        .withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER)));

        assertUnavailable(requestBlocked());
    }

    // Test 40 — sync_http500_failClosed_returns429Unavailable
    @Test
    void sync_http500_failClosed_returns429Unavailable() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(500)));

        assertUnavailable(requestBlocked());
    }

    // A response that parses as JSON but doesn't carry a recognized verdict (missing field,
    // typo, unexpected value) must be treated like a transport error — NOT silently allowed —
    // so fail-open/fail-closed is honored instead of bypassed by a non-conformant body.
    @Test
    void sync_malformedVerdict_failClosed_returns429Unavailable() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"UNKNOWN\"}")));

        assertUnavailable(requestBlocked());
    }

    // Same as above but with the verdict field missing entirely from the response body.
    @Test
    void sync_missingVerdictField_failClosed_returns429Unavailable() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"reason\":\"no verdict field at all\"}")));

        assertUnavailable(requestBlocked());
    }

    // Another request is already calling the service for this package (valid SYNC PENDING row) :
    // no second call, the scan is reported in progress.
    @Test
    void sync_concurrentCallInProgress_failClosed_returns429Pending() {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('test-scanner', 'lodash', 'npm', '4.17.21', 'SYNC', 'PENDING', ?)
                """).param(java.sql.Timestamp.from(java.time.Instant.now().plusSeconds(30))).update();

        HttpClientErrorException e = requestBlocked();

        assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"")
                .contains("\"error\":\"ExternalValidationPending\"");
        wireMock.verify(0, postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 40b — service unreachable still records TIMEOUT in cache
    @Test
    void sync_timeout_failClosed_recordsTimeoutInCache() {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withFixedDelay(3000).withStatus(200)));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException ignored) {}

        // TIMEOUT state recorded in cache
        Optional<String> entry = jdbcClient.sql("""
                SELECT status FROM external_validation_cache
                WHERE service_name='test-scanner' AND package_name='lodash'
                """).query(String.class).optional();
        assertThat(entry).isPresent();
        assertThat(entry.get()).isEqualTo("TIMEOUT");
    }

    private HttpClientErrorException requestBlocked() {
        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException e) {
            return e;
        }
        return fail("Expected a blocked request");
    }

    private static void assertUnavailable(HttpClientErrorException e) {
        assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        HttpHeaders headers = e.getResponseHeaders();
        assertThat(headers).isNotNull();
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(headers.getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_UNAVAILABLE\"")
                .contains("\"error\":\"ExternalValidationUnavailable\"")
                .contains("test-scanner");
    }
}
