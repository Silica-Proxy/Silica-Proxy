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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "silicaproxy.quarantine.fail-open=false")
class SecurityServiceFailClosedTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceFailClosedTest(SecurityService securityService, JdbcClient jdbcClient) {
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
    void shouldBlockWhenRegistryFailsAndFailClosed() {
        // Le registre distant renvoie une erreur HTTP 500
        wireMock.stubFor(get(urlEqualTo("/down-pkg-closed"))
                .willReturn(aResponse()
                        .withStatus(500)));

        DecisionResult decision = securityService.getDecision("down-pkg-closed", "1.0.0", "npm");

        // Fail-closed enabled via test properties
        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(decision.reason()).contains("Public registry is unreachable and proxy is configured in fail-closed.");
    }

    @Test
    void shouldBlockWhenRegistryTimesOutAndFailClosed() {
        // The registry remains silent longer than the read timeout (2s in test,
        // see BaseIntegrationTest) : no explicit HTTP error, just an absence of response.
        wireMock.stubFor(get(urlEqualTo("/slow-pkg-closed"))
                .willReturn(aResponse()
                        .withFixedDelay(5000)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        long start = System.currentTimeMillis();
        DecisionResult decision = securityService.getDecision("slow-pkg-closed", "1.0.0", "npm");
        long elapsedMs = System.currentTimeMillis() - start;

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(elapsedMs).isLessThan(5000);
    }
}
