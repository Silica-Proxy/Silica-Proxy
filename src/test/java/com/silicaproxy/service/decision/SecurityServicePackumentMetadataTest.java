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
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Publish-date resolution for npm packages that do NOT exist on the configured public registry
 * (JSR, private scopes) : the packument the client resolved from, then the full packument of
 * that same origin registry, must be consulted before the public registry.
 */
@TestPropertySource(properties = {
    "silicaproxy.api-fallback.osv.enabled=false",
    "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServicePackumentMetadataTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final NpmPackumentIndex npmPackumentIndex;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServicePackumentMetadataTest(
            SecurityService securityService, NpmPackumentIndex npmPackumentIndex, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.npmPackumentIndex = npmPackumentIndex;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    // Same WireMock server as the configured public registry, but a different host string : the
    // origin fallback must NOT be short-circuited as "already the public registry".
    private String originBase() {
        return "http://127.0.0.1:" + wireMock.port();
    }

    private static byte[] packument(String name, String version, String time, String tarball) {
        String body = "{\"name\":\"" + name + "\","
                + (time == null ? "" : "\"time\":{\"" + version + "\":\"" + time + "\"},")
                + "\"versions\":{\"" + version + "\":{\"name\":\"" + name + "\",\"version\":\"" + version + "\","
                + "\"dist\":{\"tarball\":\"" + tarball + "\"}}}}";
        return body.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void shouldUsePublishDateFromRelayedPackumentWithoutCallingAnyRegistry() {
        String publishedAt = Instant.now().minus(30, ChronoUnit.DAYS).toString();
        npmPackumentIndex.indexPackument(
                packument("@jsr/idx__only", "1.0.0", publishedAt, "https://npm.jsr.io/~/11/@jsr/idx__only/1.0.0.tgz"),
                null, "https://npm.jsr.io/@jsr%2fidx__only");

        DecisionResult decision = securityService.getDecision("@jsr/idx__only", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        // Public registry asked first (it wins whenever it knows the version) ; it 404s, so the
        // relayed packument's date is used without any further registry call.
        wireMock.verify(1, getRequestedFor(urlEqualTo("/@jsr/idx__only")));
        assertThat(wireMock.getAllServeEvents()).hasSize(1);
        // The learned date is persisted like a registry-resolved one.
        Integer cached = jdbcClient.sql("SELECT count(*) FROM package_metadata WHERE package_name = '@jsr/idx__only'")
                .query(Integer.class).single();
        assertThat(cached).isEqualTo(1);
    }

    @Test
    void shouldFetchFullPackumentFromOriginRegistryWhenRelayedOneHadNoTime() {
        String publishedAt = Instant.now().minus(30, ChronoUnit.DAYS).toString();
        // Abbreviated packument relayed to the client : no "time".
        npmPackumentIndex.indexPackument(
                packument("@priv/no-time", "2.0.0", null, originBase() + "/blobs/no-time-2.0.0.tgz"),
                null, originBase() + "/origin/@priv%2fno-time");
        wireMock.stubFor(get(urlEqualTo("/origin/@priv%2fno-time"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new String(packument("@priv/no-time", "2.0.0", publishedAt, "x"), StandardCharsets.UTF_8))));
        wireMock.stubFor(get(urlEqualTo("/@priv%2fno-time")).willReturn(aResponse().withStatus(404)));
        wireMock.stubFor(get(urlEqualTo("/@priv/no-time")).willReturn(aResponse().withStatus(404)));

        DecisionResult decision = securityService.getDecision("@priv/no-time", "2.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        wireMock.verify(1, getRequestedFor(urlEqualTo("/origin/@priv%2fno-time"))
                .withHeader("Accept", equalTo("application/json")));
        // Public registry asked first and 404s ; only then the origin registry answers.
        assertThat(wireMock.getAllServeEvents()).hasSize(2);
    }

    @Test
    void shouldFallBackToPublicRegistryWhenOriginIsUnknown() {
        String publishedAt = Instant.now().minus(30, ChronoUnit.DAYS).toString();
        // Learned from a tarball URL only (no origin recorded, no "time").
        npmPackumentIndex.indexPackument(
                packument("pub-only", "3.0.0", null, "https://mirror.internal/pub-only-3.0.0.tgz"), null, "");
        wireMock.stubFor(get(urlEqualTo("/pub-only"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new String(packument("pub-only", "3.0.0", publishedAt, "x"), StandardCharsets.UTF_8))));

        DecisionResult decision = securityService.getDecision("pub-only", "3.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        wireMock.verify(1, getRequestedFor(urlEqualTo("/pub-only")));
    }

    @Test
    void shouldNotDoubleQueryWhenOriginIsAlreadyThePublicRegistry() {
        String publishedAt = Instant.now().minus(30, ChronoUnit.DAYS).toString();
        String publicBase = wireMock.baseUrl();
        npmPackumentIndex.indexPackument(
                packument("same-origin", "4.0.0", null, publicBase + "/same-origin/-/same-origin-4.0.0.tgz"),
                null, publicBase + "/same-origin");
        wireMock.stubFor(get(urlEqualTo("/same-origin"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(new String(packument("same-origin", "4.0.0", publishedAt, "x"), StandardCharsets.UTF_8))));

        DecisionResult decision = securityService.getDecision("same-origin", "4.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        wireMock.verify(1, getRequestedFor(urlEqualTo("/same-origin")));
    }
}
