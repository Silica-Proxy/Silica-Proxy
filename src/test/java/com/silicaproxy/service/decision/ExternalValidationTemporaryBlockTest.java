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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// Aggregation of the temporary blocks across services : a real BLOCKED verdict (403) wins over a
// missing verdict, UNAVAILABLE is reported before PENDING, and a non-blocking service never
// blocks, even fail-closed.
class ExternalValidationTemporaryBlockTest extends BaseIntegrationTest {

    private static final String TARBALL = "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String base = "http://localhost:" + wireMock.port();
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.trigger-async-on-sync-block", () -> "false");
        registry.add("silicaproxy.external-validation.retry-after-seconds", () -> "45");

        // Blocking, fail-closed, sync
        registry.add("silicaproxy.external-validation.services.scanner-sync.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.url", () -> base + "/ext-sync");
        registry.add("silicaproxy.external-validation.services.scanner-sync.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-sync.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-sync.fail-open", () -> "false");
        registry.add("silicaproxy.external-validation.services.scanner-sync.blocking", () -> "true");

        // Blocking, fail-closed, async
        registry.add("silicaproxy.external-validation.services.scanner-async.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-async.url", () -> base + "/ext-async");
        registry.add("silicaproxy.external-validation.services.scanner-async.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.scanner-async.fail-open", () -> "false");
        registry.add("silicaproxy.external-validation.services.scanner-async.blocking", () -> "true");

        // Informational, fail-closed, async : must never block
        registry.add("silicaproxy.external-validation.services.scanner-info.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-info.url", () -> base + "/ext-info");
        registry.add("silicaproxy.external-validation.services.scanner-info.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.scanner-info.fail-open", () -> "false");
        registry.add("silicaproxy.external-validation.services.scanner-info.blocking", () -> "false");

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
        wireMock.stubFor(post(urlEqualTo("/ext-async")).willReturn(aResponse().withStatus(202)));
        wireMock.stubFor(post(urlEqualTo("/ext-info")).willReturn(aResponse().withStatus(202)));

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        proxyRestClient = RestClient.builder().requestFactory(factory).build();

        when(proxyStreamClient.streamContent(any(), any()))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream("fake-content".getBytes())));
    }

    // Most tests fire async triggers they do not wait for : let them finish before the next
    // test's setUp truncates the tables and resets WireMock.
    @AfterEach
    void drainAsyncTriggers() throws InterruptedException {
        Thread.sleep(500);
    }

    @Test
    void syncAllowed_asyncScanRunning_returns429PendingNamingOnlyTheBlockingService() {
        wireMock.stubFor(post(urlEqualTo("/ext-sync")).willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        HttpClientErrorException e = requestBlocked();

        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"")
                .contains("\"error\":\"ExternalValidationPending\"")
                .contains("External validation in progress (scanner-async); retry later.")
                .doesNotContain("scanner-info");
    }

    @Test
    void syncUnavailable_asyncScanRunning_returns429UnavailableFirst() throws InterruptedException {
        wireMock.stubFor(post(urlEqualTo("/ext-sync")).willReturn(aResponse().withStatus(500)));

        HttpClientErrorException e = requestBlocked();

        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_UNAVAILABLE\"")
                .contains("External validation service unavailable (scanner-sync); retry later.");
        // A sync service without a verdict is no BLOCKED verdict : the async scan still starts, so
        // the client's retry can be answered sooner.
        Thread.sleep(500);
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-async")));
    }

    // Every unavailable blocking service is named, sorted ; the pending one is not.
    @Test
    void severalServicesUnavailable_areAllNamedInTheReason() {
        wireMock.stubFor(post(urlEqualTo("/ext-sync")).willReturn(aResponse().withStatus(500)));
        // scanner-async's previous trigger was never acknowledged
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-async', 'lodash', 'npm', '4.17.21', 'ASYNC', 'TIMEOUT', ?)
                """).param(Timestamp.from(Instant.now().minus(1, ChronoUnit.MINUTES))).update();

        HttpClientErrorException e = requestBlocked();

        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_UNAVAILABLE\"")
                .contains("External validation service unavailable (scanner-async, scanner-sync); retry later.")
                .doesNotContain("scanner-info");
    }

    @Test
    void syncBlocked_asyncScanRunning_returns403() {
        wireMock.stubFor(post(urlEqualTo("/ext-sync"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Malicious dependency detected.\"}")));

        try {
            proxyRestClient.get().uri(TARBALL).retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseHeaders()).isNotNull();
            assertThat(e.getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isNull();
            assertThat(e.getResponseBodyAsString())
                    .contains("\"step\":\"EXTERNAL_VALIDATION\"")
                    .contains("Malicious dependency detected.");
        }
    }

    @Test
    void syncBlocked_asyncUnavailable_returns403() {
        wireMock.stubFor(post(urlEqualTo("/ext-sync"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Malicious dependency detected.\"}")));
        insertTimeout("scanner-async");

        try {
            proxyRestClient.get().uri(TARBALL).retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION\"");
        }
    }

    // scanner-info (blocking=false, fail-open=false) previous trigger failed : still never blocks.
    @Test
    void nonBlockingServiceUnavailable_neverBlocksEvenFailClosed() {
        wireMock.stubFor(post(urlEqualTo("/ext-sync")).willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));
        insertAllowed("scanner-async");
        insertTimeout("scanner-info");

        ResponseEntity<Void> response = proxyRestClient.get().uri(TARBALL).retrieve().toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void nonBlockingServiceWithoutVerdict_neverBlocksEvenFailClosed() {
        wireMock.stubFor(post(urlEqualTo("/ext-sync")).willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));
        // scanner-async already allowed the package ; scanner-info has no verdict yet (its scan is
        // triggered by this very request).
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-async', 'lodash', 'npm', '4.17.21', 'ASYNC', 'ALLOWED', ?)
                """).param(Timestamp.from(Instant.now().plus(30, ChronoUnit.MINUTES))).update();

        ResponseEntity<Void> response = proxyRestClient.get().uri(TARBALL).retrieve().toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private void insertTimeout(String service) {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES (?, 'lodash', 'npm', '4.17.21', 'ASYNC', 'TIMEOUT', ?)
                """).params(service, Timestamp.from(Instant.now().minus(1, ChronoUnit.MINUTES))).update();
    }

    private void insertAllowed(String service) {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES (?, 'lodash', 'npm', '4.17.21', 'ASYNC', 'ALLOWED', ?)
                """).params(service, Timestamp.from(Instant.now().plus(30, ChronoUnit.MINUTES))).update();
    }

    private HttpClientErrorException requestBlocked() {
        try {
            proxyRestClient.get().uri(TARBALL).retrieve().toBodilessEntity();
        } catch (HttpClientErrorException e) {
            return e;
        }
        return fail("Expected a blocked request");
    }

    private static void assertTemporaryBlock(HttpClientErrorException e) {
        assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        HttpHeaders headers = e.getResponseHeaders();
        assertThat(headers).isNotNull();
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("45");
        assertThat(headers.getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }
}
