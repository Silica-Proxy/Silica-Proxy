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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// Ordering: all SYNC services run first (in parallel, wait for all results).
// ASYNC services run second, only if all SYNC services ALLOW
// (unless trigger-async-on-sync-block=true, tested in ExternalValidationTriggerAsyncOnSyncBlockTest).
// One sync scanner-sync (blocking) + one async scanner-async (fail-open, blocking).
class ExternalValidationSyncBeforeAsyncTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String base = "http://localhost:" + wireMock.port();
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.trigger-async-on-sync-block", () -> "false");

        // Sync service
        registry.add("silicaproxy.external-validation.services.scanner-sync.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.url", () -> base + "/ext-sync");
        registry.add("silicaproxy.external-validation.services.scanner-sync.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-sync.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-sync.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.cache-ttl-minutes", () -> "60");

        // Async service
        registry.add("silicaproxy.external-validation.services.scanner-async.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-async.url", () -> base + "/ext-async");
        registry.add("silicaproxy.external-validation.services.scanner-async.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.scanner-async.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-async.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-async.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.external-validation.services.scanner-async.pending-ttl-minutes", () -> "30");

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

        // Default: async service acknowledges
        wireMock.stubFor(post(urlEqualTo("/ext-async"))
                .willReturn(aResponse().withStatus(202)));
    }

    // Test 70 — syncAllowed_asyncTriggeredAfter
    @Test
    void syncAllowed_asyncServiceIsTriggered() throws InterruptedException {
        wireMock.stubFor(post(urlEqualTo("/ext-sync"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(200); // Allow async fire-and-forget to complete

        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-sync")));
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-async")));

        // Async is PENDING (fire-and-forget)
        var asyncEntry = cacheDao.findByServiceAndPackage("scanner-async", "lodash", "npm", "4.17.21");
        assertThat(asyncEntry).isPresent();
        assertThat(asyncEntry.get().status()).isEqualTo("PENDING");
        assertThat(asyncEntry.get().mode()).isEqualTo("ASYNC");
    }

    // Test 69+71 — sync BLOCKED returns 403 and async is NOT triggered (trigger-async-on-sync-block=false)
    @Test
    void syncBlocked_returns403AndAsyncIsNotTriggered() throws InterruptedException {
        wireMock.stubFor(post(urlEqualTo("/ext-sync"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Sync blocked\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        Thread.sleep(200);

        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-sync")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-async")));
    }

    // Test 74 — noSyncServices_asyncTriggeredImmediately
    // (Requires a separate context with no sync services — tested separately)

    // Test 73 — syncAllAllowed_asyncTriggered (already covered by syncAllowed_asyncServiceIsTriggered)

    // Mirrors a production scenario : the async service (scanner-async) already recorded a
    // permanent BLOCKED verdict from a prior callback. A later request must short-circuit
    // and skip the sync service entirely — not re-call scanner-sync on every request.
    @Test
    void asyncAlreadyPermanentlyBlocked_syncServiceNeverCalled() {
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('scanner-async', 'lodash', 'npm', '4.17.21', 'Blocked by async callback')
                """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(e.getResponseBodyAsString()).contains("Blocked by async callback");
        }

        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-sync")));
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-async")));
    }

    // Verify: when sync ALLOWS, async is called with correct package payload
    @Test
    void syncAllowed_asyncPostContainsPackageAndCallbackUrl() throws InterruptedException {
        wireMock.stubFor(post(urlEqualTo("/ext-sync"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\"}")));

        proxyRestClient.get()
                .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                .retrieve().toBodilessEntity();

        Thread.sleep(200);

        wireMock.verify(postRequestedFor(urlEqualTo("/ext-async"))
                .withRequestBody(matchingJsonPath("$.packageName", equalTo("lodash")))
                .withRequestBody(matchingJsonPath("$.version", equalTo("4.17.21")))
                .withRequestBody(matchingJsonPath("$.ecosystem", equalTo("npm")))
                .withRequestBody(matchingJsonPath("$.callbackUrl")));
    }
}
