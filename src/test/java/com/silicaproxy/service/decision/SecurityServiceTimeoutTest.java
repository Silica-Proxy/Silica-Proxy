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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

// Verify that the configured read timeout (artifactsentry.http-client.registries-read-timeout-seconds,
// reduced to 2s for tests via BaseIntegrationTest) triggers correctly on a remote registry
// silent (not in error, just frozen), allowing the fail-open mechanism of SecurityService to
// activate without blocking indefinitely the calling thread.
class SecurityServiceTimeoutTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceTimeoutTest(SecurityService securityService, JdbcClient jdbcClient) {
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

    @Test
    void shouldAllowWhenRegistryTimesOutAndFailOpen() {
        // The registry never responds with error : it simply remains silent longer
        // than the configured read timeout (2s in test).
        wireMock.stubFor(get(urlEqualTo("/slow-pkg"))
                .willReturn(aResponse()
                        .withFixedDelay(5000)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        long start = System.currentTimeMillis();
        DecisionResult decision = securityService.getDecision("slow-pkg", "1.0.0", "npm");
        long elapsedMs = System.currentTimeMillis() - start;

        assertThat(decision.result()).isEqualTo("ALLOW"); // fail-open enabled by default
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        // The timeout (2s) must have triggered well before the simulated delay (5s) : the request
        // was never blocked waiting for a response that would never arrive on time.
        assertThat(elapsedMs).isLessThan(5000);
    }
}
