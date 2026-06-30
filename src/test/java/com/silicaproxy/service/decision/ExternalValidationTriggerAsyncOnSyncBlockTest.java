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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// When trigger-async-on-sync-block=true, async services are triggered even when sync BLOCKS.
// This is useful to collect deep-scan data even when a quick sync check already blocked the package.
class ExternalValidationTriggerAsyncOnSyncBlockTest extends BaseIntegrationTest {

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
        registry.add("silicaproxy.external-validation.trigger-async-on-sync-block", () -> "true");

        registry.add("silicaproxy.external-validation.services.scanner-sync.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.url", () -> base + "/ext-sync");
        registry.add("silicaproxy.external-validation.services.scanner-sync.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-sync.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-sync.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-sync.cache-ttl-minutes", () -> "60");

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

        wireMock.stubFor(post(urlEqualTo("/ext-async"))
                .willReturn(aResponse().withStatus(202)));
    }

    // Test 71b — syncBlocked_triggerAsyncTrue_asyncIsTriggered
    @Test
    void syncBlocked_triggerAsyncOnSyncBlockTrue_asyncIsStillTriggered() throws InterruptedException {
        wireMock.stubFor(post(urlEqualTo("/ext-sync"))
                .willReturn(okJson("{\"verdict\":\"BLOCKED\",\"reason\":\"Sync blocked\"}")));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException ignored) {}

        Thread.sleep(200);

        // Sync was called
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-sync")));
        // Async was ALSO triggered despite sync blocking (trigger-async-on-sync-block=true)
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-async")));
    }

    // When the package already has a permanent BLOCK verdict from a prior request (so this
    // request short-circuits and never re-calls scanner-sync), trigger-async-on-sync-block=true
    // must still fire-and-forget trigger scanner-async if it hasn't weighed in yet — the
    // short-circuit optimization must not silently narrow this flag's audit-trail purpose.
    @Test
    void permanentlyBlocked_triggerAsyncTrue_asyncStillTriggeredButSyncIsNot() throws InterruptedException {
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('scanner-sync', 'lodash', 'npm', '4.17.21', 'Already blocked previously')
                """).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException ignored) {}

        Thread.sleep(200);

        // Short-circuit avoided the redundant sync call...
        wireMock.verify(exactly(0), postRequestedFor(urlEqualTo("/ext-sync")));
        // ...but scanner-async, which never weighed in on this package yet, was still triggered.
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/ext-async")));
    }

    // Even with trigger=true, the final verdict is still BLOCKED (sync BLOCK takes priority)
    @Test
    void syncBlocked_triggerAsyncTrue_finalVerdictIsStillBlocked() {
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
    }
}
