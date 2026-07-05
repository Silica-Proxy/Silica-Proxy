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

import com.silicaproxy.config.Metrics;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.DecisionResult;
import io.micrometer.core.instrument.MeterRegistry;
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
        "silicaproxy.api-fallback.osv.enabled=false",
        "silicaproxy.api-fallback.deps-dev.enabled=true"
})
class SecurityServiceDepsDevTest extends BaseIntegrationTest {

    @DynamicPropertySource
    static void configureDepsDevUrl(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.api-fallback.deps-dev.url",
                () -> "http://localhost:" + wireMock.port());
    }

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;
    private final MeterRegistry meterRegistry;

    @Autowired
    SecurityServiceDepsDevTest(SecurityService securityService, JdbcClient jdbcClient, MeterRegistry meterRegistry) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
        this.meterRegistry = meterRegistry;
    }

    // Delta-based read: the registry is shared across every test in this class, so counters
    // persist between tests -- see identical helper/comment in SecurityServiceTest.
    private double apiCallCount(String source, String result) {
        io.micrometer.core.instrument.Counter counter = meterRegistry
                .find(Metrics.EXTERNAL_API_CALLS_METRIC)
                .tag(Metrics.TAG_SOURCE, source)
                .tag(Metrics.TAG_RESULT, result)
                .counter();
        return counter == null ? 0.0 : counter.count();
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
    void shouldBlockWhenDepsDevDetectsAdvisory() {
        stubRegistry("depsdev-vuln-pkg");
        wireMock.stubFor(get(urlEqualTo("/systems/NPM/packages/depsdev-vuln-pkg/versions/1.0.0"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"advisoryKeys\": [\"GHSA-xxxx-yyyy\"]}")));

        double before = apiCallCount(Metrics.DEPS_DEV, "BLOCK");
        DecisionResult decision = securityService.getDecision("depsdev-vuln-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("DEPS_DEV");
        assertThat(apiCallCount(Metrics.DEPS_DEV, "BLOCK") - before).isEqualTo(1.0);
    }

    @Test
    void shouldAllowWhenDepsDevFindsNoAdvisory() {
        stubRegistry("depsdev-safe-pkg");
        wireMock.stubFor(get(urlEqualTo("/systems/NPM/packages/depsdev-safe-pkg/versions/1.0.0"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"advisoryKeys\": []}")));

        double before = apiCallCount(Metrics.DEPS_DEV, "ALLOW");
        DecisionResult decision = securityService.getDecision("depsdev-safe-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("DEPS_DEV");
        assertThat(apiCallCount(Metrics.DEPS_DEV, "ALLOW") - before).isEqualTo(1.0);
    }

    @Test
    void shouldAllowWhenDepsDevApiReturnsError() {
        stubRegistry("depsdev-err-pkg");
        wireMock.stubFor(get(urlPathMatching("/systems/NPM/packages/depsdev-err-pkg/versions/.*"))
                .willReturn(aResponse().withStatus(500)));

        double before = apiCallCount(Metrics.DEPS_DEV, "ERROR");
        DecisionResult decision = securityService.getDecision("depsdev-err-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("DEPS_DEV");
        assertThat(apiCallCount(Metrics.DEPS_DEV, "ERROR") - before).isEqualTo(1.0);
    }
}
