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
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

@TestPropertySource(properties = "silicaproxy.severity-threshold.enabled=false")
class SecurityServiceSeverityDisabledTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceSeverityDisabledTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
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

    @Test
    void shouldReturnSentinelCvssWhenSeverityThresholdDisabled() {
        // With severity-threshold.enabled=false, computeMinCvss returns 11.0 (sentinel value).
        // A vulnerability with CVSS 9.8 which would normally be blocked for npm (HIGH threshold=9.0)
        // must NOT be detected by the SQL query (9.8 < 11.0) → the fallback chain
        // takes over and the package is allowed (spec §4.2, SecurityService L179).
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-severity-disabled', 'OSV', 'high-cvss-pkg', 'npm', 'High CVSS bug', '["1.0.0"]'::jsonb, 9.8)
                """).update();

        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/high-cvss-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"high-cvss-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("high-cvss-pkg", "1.0.0", "npm");

        assertThat(decision.sourceType()).isNotEqualTo("PUBLIC_VULN");
        assertThat(decision.result()).isEqualTo("ALLOW");
    }

    @Test
    void shouldStillBlockMalwareByIdWhenSeverityThresholdDisabled() {
        // Malware advisories carry cvss_score=0.0 (no CVSS vector exists for "malicious or not").
        // The "id LIKE 'MAL-%'" bypass in DecisionDao is a plain SQL OR, independent of :minCvss,
        // so it must still block even though computeMinCvss() returns the 11.0 sentinel here.
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('MAL-severity-disabled-1', 'OSV', 'malware-pkg-1', 'npm', 'Known malware', '["1.0.0"]'::jsonb, 0.0)
                """).update();

        DecisionResult decision = securityService.getDecision("malware-pkg-1", "1.0.0", "npm");

        assertThat(decision.sourceType()).isEqualTo("PUBLIC_VULN");
        assertThat(decision.result()).isEqualTo("BLOCK");
    }

    @Test
    void shouldStillBlockMalwareBySourceWhenSeverityThresholdDisabled() {
        // Same bypass, triggered via source='OPENSSF' instead of the 'MAL-' id prefix.
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('GHSA-severity-disabled-2', 'OPENSSF', 'malware-pkg-2', 'npm', 'Known malware', '["1.0.0"]'::jsonb, 0.0)
                """).update();

        DecisionResult decision = securityService.getDecision("malware-pkg-2", "1.0.0", "npm");

        assertThat(decision.sourceType()).isEqualTo("PUBLIC_VULN");
        assertThat(decision.result()).isEqualTo("BLOCK");
    }
}
