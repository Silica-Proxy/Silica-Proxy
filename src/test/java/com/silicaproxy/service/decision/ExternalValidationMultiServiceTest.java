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
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// Two sync services (scanner-a and scanner-b) — most-restrictive-wins semantics.
// All sync services run in parallel; a single BLOCKED verdict blocks the package.
class ExternalValidationMultiServiceTest extends BaseIntegrationTest {

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

        registry.add("silicaproxy.external-validation.services.scanner-a.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-a.url", () -> base + "/ext-a");
        registry.add("silicaproxy.external-validation.services.scanner-a.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-a.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-a.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-a.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-a.cache-ttl-minutes", () -> "60");

        registry.add("silicaproxy.external-validation.services.scanner-b.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-b.url", () -> base + "/ext-b");
        registry.add("silicaproxy.external-validation.services.scanner-b.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-b.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-b.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-b.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-b.cache-ttl-minutes", () -> "60");

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

    // Test 30 — oneBlockOneAllow → BLOCKED (most restrictive wins)
    @Test
    void multiService_oneBlockOneAllow_isBlocked() {
        wireMock.stubFor(post(urlEqualTo("/ext-a"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"A blocked it\"}")));
        wireMock.stubFor(post(urlEqualTo("/ext-b"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("A blocked it");
        }

        // Both services were called (ran in parallel)
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // Test 31 — bothAllow → requestForwarded
    @Test
    void multiService_bothAllow_requestForwarded() {
        wireMock.stubFor(post(urlEqualTo("/ext-a"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));
        wireMock.stubFor(post(urlEqualTo("/ext-b"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // Test 32 — most-restrictive-wins regardless of which service blocked
    // (scanner-a ALLOWS, scanner-b BLOCKS → still 403; mirrors test 30 with roles reversed)
    // blocking=false multi-service behaviour is covered by ExternalValidationSyncNonBlockingTest
    @Test
    void multiService_secondServiceBlocks_isBlocked() {
        wireMock.stubFor(post(urlEqualTo("/ext-a"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));
        wireMock.stubFor(post(urlEqualTo("/ext-b"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"B blocked it\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("B blocked it");
        }

        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // Test 47 — bothPending_bothFailOpen → requestForwarded
    @Test
    void multiService_bothPending_bothFailOpen_requestForwarded() {
        // Pre-populate both as PENDING (fail-open means allow)
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-a', 'lodash', 'npm', '4.17.21', 'SYNC', 'PENDING', ?)
                """).param(Timestamp.from(Instant.now().plus(30, ChronoUnit.MINUTES))).update();
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-b', 'lodash', 'npm', '4.17.21', 'SYNC', 'PENDING', ?)
                """).param(Timestamp.from(Instant.now().plus(30, ChronoUnit.MINUTES))).update();

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        // No new service calls (used existing PENDING cache)
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // Test 49 — oneBlockingBlocked_otherPendingFailOpen → BLOCKED (most restrictive wins)
    @Test
    void multiService_oneBlockedOtherPending_isBlocked() {
        // scanner-a: BLOCKED verdict in verdicts table
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('scanner-a', 'lodash', 'npm', '4.17.21', 'Scanner A blocked')
                """).update();

        // scanner-b: still PENDING (fail-open → would allow by itself)
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-b', 'lodash', 'npm', '4.17.21', 'SYNC', 'PENDING', ?)
                """).param(Timestamp.from(Instant.now().plus(30, ChronoUnit.MINUTES))).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        // The permanent verdict from scanner-a short-circuits the whole check —
        // scanner-b is never even queried, despite being PENDING/fail-open.
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // A permanent BLOCK from one service must short-circuit the whole check, skipping
    // network calls to every other configured service entirely — not just when the
    // other service happens to be PENDING/cached, but even from a completely cold state.
    @Test
    void multiService_permanentBlockOnOneService_otherServiceNeverCalled() {
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('scanner-a', 'lodash', 'npm', '4.17.21', 'Scanner A permanently blocked it')
                """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("Scanner A permanently blocked it");
        }

        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // Repeated requests after the permanent verdict was recorded must keep short-circuiting —
    // this is the scenario reported in production : sync/async services kept being re-called
    // on every single request even though one of them had already permanently blocked the package.
    @Test
    void multiService_permanentBlock_repeatedRequestsNeverCallServicesAgain() {
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('scanner-a', 'lodash', 'npm', '4.17.21', 'Scanner A permanently blocked it')
                """).update();

        for (int i = 0; i < 3; i++) {
            try {
                proxyRestClient.get()
                        .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                        .retrieve().toBodilessEntity();
                fail("Expected 403");
            } catch (HttpClientErrorException e) {
                assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            }
        }

        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-b")));
    }

    // Test 50 — noEnabledServices → chain continues to OSV (not tested here since OSV disabled)
    // Verified in ExternalValidationNoServicesTest

    // Test 66 — oneAllowed_onePendingFailClosed → BLOCKED (fail-closed on pending)
    // (Requires scanner-b with fail-open=false — tested in ExternalValidationMultiServiceFailClosedTest)

    // Both services agree: both ALLOWED (from cache, no new calls)
    @Test
    void multiService_bothCachedAllowed_noServiceCall() {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-a', 'lodash', 'npm', '4.17.21', 'SYNC', 'ALLOWED', ?)
                """).param(Timestamp.from(Instant.now().plus(60, ChronoUnit.MINUTES))).update();
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('scanner-b', 'lodash', 'npm', '4.17.21', 'SYNC', 'ALLOWED', ?)
                """).param(Timestamp.from(Instant.now().plus(60, ChronoUnit.MINUTES))).update();

        var response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-a")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-b")));
    }
}
