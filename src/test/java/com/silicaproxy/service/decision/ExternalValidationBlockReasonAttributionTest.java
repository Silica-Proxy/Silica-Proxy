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

// buildBlockReason() must only attribute the 403 reason to a service configured blocking=true —
// a non-blocking (informational) service's stored verdict must never be reported as "the" reason
// the package was blocked, even if it's the only verdict present in the table.
class ExternalValidationBlockReasonAttributionTest extends BaseIntegrationTest {

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

        // Blocking service — fail-closed on timeout, never writes a verdict in that case.
        registry.add("silicaproxy.external-validation.services.scanner-strict.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-strict.url", () -> base + "/ext-strict");
        registry.add("silicaproxy.external-validation.services.scanner-strict.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-strict.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-strict.fail-open", () -> "false");
        registry.add("silicaproxy.external-validation.services.scanner-strict.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-strict.cache-ttl-minutes", () -> "60");

        // Informational service — never enforces, but may have a stored verdict/reason.
        registry.add("silicaproxy.external-validation.services.scanner-info.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-info.url", () -> base + "/ext-info");
        registry.add("silicaproxy.external-validation.services.scanner-info.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.scanner-info.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.scanner-info.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.scanner-info.blocking", () -> "false");
        registry.add("silicaproxy.external-validation.services.scanner-info.cache-ttl-minutes", () -> "60");

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

    @Test
    void nonBlockingServiceReason_isNeverAttributedToTheBlock() {
        // scanner-info (blocking=false) has a stored informational verdict with a reason.
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('scanner-info', 'lodash', 'npm', '4.17.21', 'Informational note from scanner-info')
                """).update();

        // scanner-strict (blocking=true, fail-open=false) times out — fail-closed BLOCK,
        // but writes no verdict of its own.
        wireMock.stubFor(post(urlEqualTo("/ext-strict"))
                .willReturn(aResponse().withFixedDelay(3000).withStatus(200)));

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                    .retrieve().toBodilessEntity();
            fail("Expected 403");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            // Must NOT show scanner-info's informational reason — that service never blocks.
            assertThat(e.getResponseBodyAsString()).doesNotContain("Informational note from scanner-info");
            assertThat(e.getResponseBodyAsString()).contains("Package blocked by external validation service.");
        }
    }
}
