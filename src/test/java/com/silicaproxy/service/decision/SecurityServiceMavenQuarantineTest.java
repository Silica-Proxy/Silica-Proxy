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

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "silicaproxy.quarantine.ecosystems.maven.enabled=true")
class SecurityServiceMavenQuarantineTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceMavenQuarantineTest(SecurityService securityService, JdbcClient jdbcClient) {
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
    void shouldBlockMavenPackageBelowQuarantineThreshold() {
        // Maven : min-age-days = 5 ; age = 3 < 5 → quarantaine
        Instant publishedAt = Instant.now().minus(3, ChronoUnit.DAYS);
        wireMock.stubFor(head(urlMatching("/maven2/com/example/new-artifact/1\\.0\\.0/.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", formatHttpDate(publishedAt))));

        DecisionResult decision = securityService.getDecision("com.example:new-artifact", "1.0.0", "maven");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_QUARANTINE");
    }

    @Test
    void shouldAllowMavenPackageAboveQuarantineThreshold() {
        // Maven : min-age-days = 5 ; age = 6 >= 5 → pas de quarantaine
        Instant publishedAt = Instant.now().minus(6, ChronoUnit.DAYS);
        wireMock.stubFor(head(urlMatching("/maven2/com/example/old-artifact/1\\.0\\.0/.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", formatHttpDate(publishedAt))));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("com.example:old-artifact", "1.0.0", "maven");

        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_QUARANTINE");
        assertThat(decision.result()).isEqualTo("ALLOW");
    }

    private String formatHttpDate(Instant instant) {
        return java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME
                .format(instant.atZone(java.time.ZoneOffset.UTC));
    }
}
