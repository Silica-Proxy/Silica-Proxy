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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

@TestPropertySource(properties = {
        "silicaproxy.api-fallback.osv.enabled=true",
        "silicaproxy.api-fallback.deps-dev.enabled=true"
})
class SecurityServiceFallbackChainTest extends BaseIntegrationTest {

    @DynamicPropertySource
    static void configureUrls(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.api-fallback.deps-dev.url",
                () -> "http://localhost:" + wireMock.port());
    }

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceFallbackChainTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDbAndWiremock() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    private void stubRegistry(String packageName) {
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/" + packageName))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt + "\"}," +
                                "  \"versions\": {\"1.0.0\": {}}" +
                                "}")));
    }

    @Test
    void shouldStopAtOsvAndNotCallDepsDevWhenOsvBlocks() {
        stubRegistry("chain-vuln-pkg");
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"vulns\": [{\"id\": \"CVE-2024-001\"}]}")));

        DecisionResult decision = securityService.getDecision("chain-vuln-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("OSV_LIVE");
        wireMock.verify(0, getRequestedFor(urlPathMatching("/systems/.*")));
    }

    @Test
    void shouldStopAtOsvAndNotCallDepsDevWhenOsvFindsNoIssues() {
        stubRegistry("chain-safe-pkg");
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("chain-safe-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("OSV_LIVE");
        wireMock.verify(0, getRequestedFor(urlPathMatching("/systems/.*")));
    }

    @Test
    void shouldNotCallDepsDevWhenOsvReturnsError() {
        // OSV enabled + deps.dev enabled : if OSV returns 500 (fail-open -> ALLOW),
        // the chain stops at OSV. deps.dev must not be called.
        stubRegistry("osv-500-chain-pkg");
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withStatus(500)));

        DecisionResult decision = securityService.getDecision("osv-500-chain-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("OSV_LIVE");
        wireMock.verify(0, getRequestedFor(urlPathMatching("/systems/.*")));
    }
}
