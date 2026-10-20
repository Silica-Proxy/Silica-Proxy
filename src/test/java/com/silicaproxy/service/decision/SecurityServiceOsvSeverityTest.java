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
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.Verdict;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The live OSV API reports every advisory of a version : the npm threshold of the test profile
 * (max-allowed-severity HIGH, max-allowed-cvss 9.0) must apply to them exactly as it does to the
 * local tables, instead of blocking on any advisory.
 */
@TestPropertySource(properties = {
        "silicaproxy.api-fallback.osv.enabled=true",
        "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServiceOsvSeverityTest extends BaseIntegrationTest {

    private static final String HIGH_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"; // 7.5
    private static final String CRITICAL_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; // 9.8

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceOsvSeverityTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDbAndWiremock() {
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    private DecisionResult decideWithOsvAnswer(String packageName, String osvBody) {
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/" + packageName))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"1.0.0\": \"" + publishedAt + "\"}, \"versions\": {\"1.0.0\": {}}}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(osvBody)));
        return securityService.getDecision(packageName, "1.0.0", "npm", "");
    }

    @Test
    void highAdvisoryBelowNpmThresholdShouldBeAllowed() {
        DecisionResult decision = decideWithOsvAnswer("osv-high-pkg", """
                {"vulns": [{"id": "GHSA-high", "severity": [{"type": "CVSS_V3", "score": "%s"}]}]}
                """.formatted(HIGH_V3));

        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.OSV_LIVE);
    }

    @Test
    void criticalAdvisoryShouldBeBlocked() {
        DecisionResult decision = decideWithOsvAnswer("osv-critical-pkg", """
                {"vulns": [{"id": "GHSA-crit", "severity": [{"type": "CVSS_V3", "score": "%s"}]}]}
                """.formatted(CRITICAL_V3));

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.OSV_LIVE);
        assertThat(decision.reason()).contains("GHSA-crit");
    }

    @Test
    void unscoredAdvisoryShouldTakeTheScoreOfItsAliasInTheSameAnswer() {
        DecisionResult decision = decideWithOsvAnswer("osv-alias-pkg", """
                {"vulns": [
                  {"id": "PYSEC-x", "aliases": ["CVE-x", "GHSA-x"]},
                  {"id": "GHSA-x", "aliases": ["CVE-x"], "severity": [{"type": "CVSS_V3", "score": "%s"}]}
                ]}
                """.formatted(HIGH_V3));

        // 7.5 is allowed on npm (HIGH / 9.0) : the unscored PYSEC must not block on its own
        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void orphanAdvisoryShouldBeBlockedByDefault() {
        DecisionResult decision = decideWithOsvAnswer("osv-orphan-pkg", """
                {"vulns": [{"id": "PYSEC-orphan", "aliases": ["CVE-orphan"]}]}
                """);

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.OSV_LIVE);
    }

    @Test
    void malwareShouldBeBlocked() {
        DecisionResult decision = decideWithOsvAnswer("osv-malware-pkg", """
                {"vulns": [{"id": "MAL-2025-1"}]}
                """);

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.reason()).contains("MAL-2025-1");
    }
}
