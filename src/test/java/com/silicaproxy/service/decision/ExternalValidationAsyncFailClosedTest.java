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
import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import io.micrometer.core.instrument.Counter;
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
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// External validation — async mode, fail-open=false (fail-closed).
// No verdict yet means a temporary block : 429 + Retry-After + no-store, the source telling a scan
// in progress (EXTERNAL_VALIDATION_PENDING) from an unreachable service (EXTERNAL_VALIDATION_UNAVAILABLE).
class ExternalValidationAsyncFailClosedTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @Autowired
    private MeterRegistry meterRegistry;

    private RestClient proxyRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "false");
        registry.add("silicaproxy.external-validation.services.test-scanner.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.external-validation.services.test-scanner.pending-ttl-minutes", () -> "30");
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

        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(202)));
    }

    // Test 41 — async_firstRequest_failClosed_storesPendingAndBlocks
    @Test
    void async_firstRequest_failClosed_returns429PendingWhileScanRuns() throws InterruptedException {
        double before = blockReasonCount(Metrics.REASON_PENDING);
        HttpClientErrorException e = requestBlocked();
        assertTemporaryBlock(e);
        assertThat(blockReasonCount(Metrics.REASON_PENDING) - before).isEqualTo(1.0);
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"")
                .contains("\"error\":\"ExternalValidationPending\"")
                .contains("test-scanner");

        Thread.sleep(500); // Fire-and-forget async task writes DB and calls WireMock after the response

        // PENDING entry stored
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("PENDING");

        // Async call was made (fire-and-forget)
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 24 — async_pendingState_failClosed_returns429Pending
    @Test
    void async_pendingAlreadyExists_failClosed_returns429Pending() throws InterruptedException {
        // Pre-populate PENDING entry (simulates in-progress check)
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (callback_token, service_name, package_name, ecosystem, package_version,
                     mode, status, expires_at)
                VALUES (?, 'test-scanner', 'lodash', 'npm', '4.17.21', 'ASYNC', 'PENDING', ?)
                """).params(java.util.UUID.randomUUID(),
                Timestamp.from(Instant.now().plus(30, ChronoUnit.MINUTES))).update();

        HttpClientErrorException e = requestBlocked();
        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"");

        Thread.sleep(500); // Ensure the fire-and-forget task (which exits early on valid PENDING) completes

        // No new async call (existing PENDING reused)
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 43 — async_initialPostFails_failClosed_returns429
    @Test
    void async_initialPostFails_failClosed_returns429() throws InterruptedException {
        wireMock.resetAll();
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(500)));

        // The state is read before the background trigger : the first request sees a scan starting.
        HttpClientErrorException e = requestBlocked();
        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"");

        Thread.sleep(500); // Wait for async task to complete and update DB

        // Failed POST → no orphan PENDING; entry is TIMEOUT (not left as PENDING)
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("TIMEOUT");
    }

    // No callback within pending-ttl, the cleanup sweep not run yet (row still PENDING, expired) :
    // same as a swept TIMEOUT row, the service is reported unavailable and a new scan starts.
    @Test
    void async_pendingExpiredNotSwept_failClosed_returns429UnavailableAndRetriggers() throws InterruptedException {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (callback_token, service_name, package_name, ecosystem, package_version,
                     mode, status, expires_at)
                VALUES (?, 'test-scanner', 'lodash', 'npm', '4.17.21', 'ASYNC', 'PENDING', ?)
                """).params(java.util.UUID.randomUUID(),
                Timestamp.from(Instant.now().minus(1, ChronoUnit.MINUTES))).update();

        double before = blockReasonCount(Metrics.REASON_UNAVAILABLE);
        HttpClientErrorException e = requestBlocked();
        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString())
                .contains("\"step\":\"EXTERNAL_VALIDATION_UNAVAILABLE\"")
                .contains("\"error\":\"ExternalValidationUnavailable\"")
                .contains("test-scanner");
        assertThat(blockReasonCount(Metrics.REASON_UNAVAILABLE) - before).isEqualTo(1.0);

        Thread.sleep(500); // Fire-and-forget re-trigger
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
        assertThat(requestBlocked().getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"");
    }

    // Test 46 — async_pendingTimeout_failClosed_returns429
    @Test
    void async_pendingTimeout_failClosed_returns429() throws InterruptedException {
        // Pre-populate TIMEOUT entry (pending expired without callback)
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('test-scanner', 'lodash', 'npm', '4.17.21', 'ASYNC', 'TIMEOUT', ?)
                """).param(Timestamp.from(Instant.now().minus(1, ChronoUnit.MINUTES))).update();

        // Fail-closed: re-triggers async check but still blocks the current request (temporarily),
        // reporting the previous failure
        HttpClientErrorException e = requestBlocked();
        assertTemporaryBlock(e);
        assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION_UNAVAILABLE\"");

        Thread.sleep(1000); // Fire-and-forget async task calls WireMock and updates DB after the response

        // A new async check is triggered (re-scan)
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
        // Cache is back to PENDING for the new check
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("PENDING");
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

    private double blockReasonCount(String reason) {
        Counter counter = meterRegistry.find(Metrics.BLOCK_REASON_METRIC).tag(Metrics.TAG_REASON, reason).counter();
        return counter == null ? 0.0 : counter.count();
    }

    // A block that only waits for a verdict : 429, never 403, never cached by a repository manager.
    private static void assertTemporaryBlock(HttpClientErrorException e) {
        assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        HttpHeaders headers = e.getResponseHeaders();
        assertThat(headers).isNotNull();
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        assertThat(headers.getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
    }
}
