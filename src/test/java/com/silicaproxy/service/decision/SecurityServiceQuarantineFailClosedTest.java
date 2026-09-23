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
import com.silicaproxy.model.dto.DecisionResult;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With {@code silicaproxy.quarantine.fail-open=false}, a package whose publish date cannot be
 * resolved is blocked, and the unresolved-date metric records the BLOCK verdict.
 */
@TestPropertySource(properties = {
    "silicaproxy.quarantine.fail-open=false",
    "silicaproxy.api-fallback.osv.enabled=false",
    "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServiceQuarantineFailClosedTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;
    private final MeterRegistry meterRegistry;

    @Autowired
    SecurityServiceQuarantineFailClosedTest(
            SecurityService securityService, JdbcClient jdbcClient, MeterRegistry meterRegistry) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
        this.meterRegistry = meterRegistry;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    private double unresolved(String ecosystem, String verdict) {
        Counter counter = meterRegistry.find(Metrics.PUBLISH_DATE_UNRESOLVED_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .tag(Metrics.TAG_VERDICT, verdict)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    @Test
    void shouldBlockNpmPackageWhenPublicRegistryIsDown() {
        wireMock.stubFor(get(urlEqualTo("/closed-down-pkg")).willReturn(aResponse().withStatus(503)));
        double before = unresolved("npm", "BLOCK");

        DecisionResult decision = securityService.getDecision("closed-down-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(unresolved("npm", "BLOCK")).isEqualTo(before + 1);
    }

    @Test
    void shouldBlockPypiPackageUnknownToTheRegistry() {
        wireMock.stubFor(get(urlEqualTo("/pypi/closed-unknown-pkg/json")).willReturn(aResponse().withStatus(404)));
        double before = unresolved("pypi", "BLOCK");

        DecisionResult decision = securityService.getDecision("closed-unknown-pkg", "1.0.0", "pypi", "");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(unresolved("pypi", "BLOCK")).isEqualTo(before + 1);
    }
}
