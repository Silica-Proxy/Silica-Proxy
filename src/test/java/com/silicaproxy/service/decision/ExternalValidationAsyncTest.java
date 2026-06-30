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
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import com.silicaproxy.model.entity.ExternalValidationVerdictEntry;
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
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// External validation — async mode, fail-open=true, blocking=true.
// The external service POSTs a callback when it has a verdict.
// Pending requests apply fail-open while waiting.
class ExternalValidationAsyncTest extends BaseIntegrationTest {

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
    private RestClient localRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.callback-base-url",
                () -> "http://localhost:0");  // overridden per-test when callbackUrl verification needed
        registry.add("silicaproxy.external-validation.trigger-async-on-sync-block", () -> "false");
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "true");
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
        localRestClient = RestClient.create("http://localhost:" + port);

        when(proxyStreamClient.streamContent(any(), any()))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream("fake-content".getBytes())));

        // Default: async service acknowledges with 202
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(202)));
    }

    // Test 23 — async_firstRequest_storesPendingAndAllows (fail-open)
    @Test
    void async_firstRequest_storesPendingInDbAndAllowsFailOpen() throws InterruptedException {
        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        Thread.sleep(500); // Fire-and-forget async task writes DB and calls WireMock after the response

        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));

        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("PENDING");
        assertThat(entry.get().mode()).isEqualTo("ASYNC");
        assertThat(entry.get().callbackToken()).isNotNull();
        assertThat(entry.get().expiresAt()).isAfter(Instant.now().plus(29, ChronoUnit.MINUTES));
    }

    // Test 25 — async_afterCallback_blocked_returns403
    @Test
    void async_afterBlockedCallback_subsequentRequestReturns403() throws InterruptedException {
        // First request triggers async check
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(500); // Fire-and-forget async task writes token to DB after the response

        // Read token from DB
        UUID token = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21")
                .orElseThrow().callbackToken();

        // Simulate external service callback with BLOCKED verdict
        localRestClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"BLOCKED\",\"reason\":\"Malicious supply chain\"}")
                .retrieve().toBodilessEntity();

        // Next request hits the permanent verdict
        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("Malicious supply chain");
        }

        // External service NOT called again (verdict cached permanently)
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 26 — async_afterCallback_allowed_requestForwarded
    @Test
    void async_afterAllowedCallback_subsequentRequestForwarded() throws InterruptedException {
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(500); // Fire-and-forget async task writes token to DB after the response

        UUID token = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21")
                .orElseThrow().callbackToken();

        localRestClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"ALLOWED\",\"reason\":\"No threats found\"}")
                .retrieve().toBodilessEntity();

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        // External service called only once; second request used cached ALLOWED
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 42 — async_initialPostFails_failOpen_requestForwarded
    @Test
    void async_initialPostFails_failOpen_requestIsForwarded() throws InterruptedException {
        wireMock.resetAll();
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(500)));

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        Thread.sleep(500); // Wait for async task to complete and update DB

        // Failed POST → no orphan PENDING; entry is TIMEOUT (not left as PENDING)
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("TIMEOUT");
    }

    // Test 45 — async_pendingTimeout_failOpen_retriggersAsync
    @Test
    void async_pendingTimeout_failOpen_retriggersAsyncCheck() throws InterruptedException {
        // Pre-populate TIMEOUT entry (pending timed out without callback)
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (service_name, package_name, ecosystem, package_version, mode, status, expires_at)
                VALUES ('test-scanner', 'lodash', 'npm', '4.17.21', 'ASYNC', 'TIMEOUT', ?)
                """).param(Timestamp.from(Instant.now().minus(1, ChronoUnit.MINUTES))).update();

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toEntity(byte[].class);

        // Fail-open: request allowed while new async check is triggered
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        Thread.sleep(500); // Fire-and-forget async task writes DB and calls WireMock after the response

        // New async call was made
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
        // Cache is now PENDING again
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry.get().status()).isEqualTo("PENDING");
    }

    // Test 65 — async_postBodyContainsCallbackUrlField
    @Test
    void async_postBodyContainsCallbackUrlField() throws InterruptedException {
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(500); // Fire-and-forget async task calls WireMock after the response

        // Verify the POST body contains a callbackUrl field
        wireMock.verify(postRequestedFor(urlEqualTo("/external-validate"))
                .withRequestBody(matchingJsonPath("$.callbackUrl")));

        // Verify it points to the callback endpoint path
        List<com.github.tomakehurst.wiremock.verification.LoggedRequest> requests =
                wireMock.findAll(postRequestedFor(urlEqualTo("/external-validate")));
        assertThat(requests).hasSize(1);
        String body = requests.get(0).getBodyAsString();
        assertThat(body).contains("/external-validation/callback/");
    }

    // Test 23b — async_secondPendingRequest_doesNotRetrigger
    @Test
    void async_secondRequestWhilePending_doesNotRetriggerAsyncCall() throws InterruptedException {
        // First request → async call triggered, PENDING stored
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(500); // Fire-and-forget async task writes PENDING to DB before second request

        // Second request while PENDING → returns fail-open but does NOT trigger another async call
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(500); // Wait for any async tasks to complete

        // External service called exactly once
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    // Test 25b — BLOCKED callback writes to permanent verdicts table
    @Test
    void async_blockedCallback_storedInVerdictsTableNotCache() throws InterruptedException {
        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(500); // Fire-and-forget async task writes token to DB after the response

        UUID token = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21")
                .orElseThrow().callbackToken();

        localRestClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"BLOCKED\",\"reason\":\"Permanent block\"}")
                .retrieve().toBodilessEntity();

        // Removed from cache (BLOCKED is permanent)
        assertThat(cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21"))
                .isEmpty();

        // Stored permanently in verdicts
        Optional<ExternalValidationVerdictEntry> verdict = verdictsDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(verdict).isPresent();
        assertThat(verdict.get().reason()).isEqualTo("Permanent block");
    }
}
