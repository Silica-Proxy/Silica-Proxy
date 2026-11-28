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
import org.springframework.http.MediaType;
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
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// External validation — async, blocking, fail-closed, with await-verdict-seconds : the first download
// of a version not scanned yet is held until the scan calls back, instead of an immediate 429.
class ExternalValidationAsyncAwaitVerdictTest extends BaseIntegrationTest {

    private static final int AWAIT_SECONDS = 3;
    private static final String SERVICE = "test-scanner";

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private MeterRegistry meterRegistry;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.await-poll-interval-millis", () -> "100");
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "false");
        registry.add("silicaproxy.external-validation.services.test-scanner.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.external-validation.services.test-scanner.pending-ttl-minutes", () -> "30");
        registry.add("silicaproxy.external-validation.services.test-scanner.await-verdict-seconds",
                () -> Integer.toString(AWAIT_SECONDS));
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

        // Plain acknowledgment : the verdict comes later, by callback.
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(202)));
    }

    @Test
    void allowedCallbackDuringWait_firstDownloadSucceeds() {
        double resolvedBefore = awaitCount(Metrics.OUTCOME_RESOLVED);
        CompletableFuture<Void> scanner = resolveAfterDelay(token -> sendCallback(token, "ALLOWED"));

        Instant start = Instant.now();
        ResponseEntity<Void> response = download();
        Duration elapsed = Duration.between(start, Instant.now());
        scanner.join();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(elapsed).isLessThan(Duration.ofSeconds(AWAIT_SECONDS));
        assertThat(awaitCount(Metrics.OUTCOME_RESOLVED) - resolvedBefore).isEqualTo(1.0);
    }

    @Test
    void blockedCallbackDuringWait_firstDownloadIsBlockedForGood() {
        CompletableFuture<Void> scanner = resolveAfterDelay(token -> sendCallback(token, "BLOCKED"));

        assertThatThrownBy(this::download)
                .isInstanceOfSatisfying(HttpClientErrorException.class, e -> {
                    assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION\"");
                });
        scanner.join();
    }

    // The callback reached another instance : only the shared table changed, and the held request
    // still sees it.
    @Test
    void verdictWrittenByAnotherInstance_firstDownloadSucceeds() {
        CompletableFuture<Void> otherInstance = resolveAfterDelay(token -> cacheDao.updateToAllowedByToken(
                token, "No threats", Instant.now().plus(60, ChronoUnit.MINUTES)));

        ResponseEntity<Void> response = download();
        otherInstance.join();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void noCallbackWithinWait_temporary429AfterTheWait() {
        double expiredBefore = awaitCount(Metrics.OUTCOME_EXPIRED);

        Instant start = Instant.now();
        assertThatThrownBy(this::download)
                .isInstanceOfSatisfying(HttpClientErrorException.class, e -> {
                    assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                    assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"");
                });
        Duration elapsed = Duration.between(start, Instant.now());

        assertThat(elapsed).isGreaterThanOrEqualTo(Duration.ofSeconds(AWAIT_SECONDS).minusMillis(200));
        assertThat(awaitCount(Metrics.OUTCOME_EXPIRED) - expiredBefore).isEqualTo(1.0);
        // The scan keeps running : the entry stays PENDING for the client's retry.
        assertThat(cacheDao.findByServiceAndPackage(SERVICE, "lodash", "npm", "4.17.21"))
                .get().extracting(ExternalValidationCacheEntry::status).isEqualTo("PENDING");
    }

    // A trigger the service did not acknowledge leaves no PENDING scan to wait for : 429 at once.
    @Test
    void triggerNotAcknowledged_noWait() {
        wireMock.resetAll();
        wireMock.stubFor(post(urlEqualTo("/external-validate")).willReturn(aResponse().withStatus(500)));

        Instant start = Instant.now();
        assertThatThrownBy(this::download)
                .isInstanceOfSatisfying(HttpClientErrorException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));

        assertThat(Duration.between(start, Instant.now())).isLessThan(Duration.ofSeconds(AWAIT_SECONDS));
    }

    private ResponseEntity<Void> download() {
        return proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();
    }

    // Plays the scanner : waits for the PENDING entry written by the trigger, then resolves it after
    // a delay well inside AWAIT_SECONDS.
    private CompletableFuture<Void> resolveAfterDelay(Consumer<UUID> resolve) {
        return CompletableFuture.runAsync(() -> {
            UUID token = awaitPendingToken();
            sleep(800);
            resolve.accept(token);
        });
    }

    private UUID awaitPendingToken() {
        Instant deadline = Instant.now().plusSeconds(AWAIT_SECONDS);
        while (Instant.now().isBefore(deadline)) {
            UUID token = cacheDao.findByServiceAndPackage(SERVICE, "lodash", "npm", "4.17.21")
                    .filter(e -> "PENDING".equals(e.status()))
                    .map(ExternalValidationCacheEntry::callbackToken)
                    .orElse(null);
            if (token != null) {
                return token;
            }
            sleep(50);
        }
        throw new AssertionError("No PENDING entry written by the trigger");
    }

    private void sendCallback(UUID token, String verdict) {
        RestClient.create().post()
                .uri("http://localhost:" + port + "/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"" + verdict + "\",\"reason\":\"test verdict\"}")
                .retrieve().toBodilessEntity();
    }

    private double awaitCount(String outcome) {
        Counter counter = meterRegistry.find(Metrics.AWAIT_METRIC)
                .tag(Metrics.TAG_SERVICE, SERVICE).tag(Metrics.TAG_OUTCOME, outcome).counter();
        return counter == null ? 0.0 : counter.count();
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
