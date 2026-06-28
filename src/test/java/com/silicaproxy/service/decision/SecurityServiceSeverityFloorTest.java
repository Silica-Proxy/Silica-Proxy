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

import static org.assertj.core.api.Assertions.assertThat;

@TestPropertySource(properties = {
        "silicaproxy.severity-threshold.ecosystems.low-eco.max-allowed-severity=LOW",
        "silicaproxy.severity-threshold.ecosystems.low-eco.max-allowed-cvss=10.0",
        "silicaproxy.severity-threshold.ecosystems.critical-eco.max-allowed-severity=CRITICAL",
        "silicaproxy.severity-threshold.ecosystems.critical-eco.max-allowed-cvss=11.0"
})
class SecurityServiceSeverityFloorTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceSeverityFloorTest(SecurityService securityService, JdbcClient jdbcClient) {
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
    void shouldComputeCorrectCvssFloorForEachSeverityLevel() {
        // Verify that getSeverityPlancher calculates the correct CVSS floor for each severity
        // level (without custom mappings in database) (spec §4.2).

        // LOW → nextSeverity=MEDIUM → plancher=4.0 ; min(10.0, 4.0) = 4.0
        // CVSS 4.5 >= 4.0 → BLOCK from PUBLIC_VULN
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-low-floor', 'OSV', 'low-floor-pkg', 'low-eco', 'LOW floor test', '["1.0.0"]'::jsonb, 4.5)
                """).update();
        DecisionResult lowDecision = securityService.getDecision("low-floor-pkg", "1.0.0", "low-eco");
        assertThat(lowDecision.result()).as("LOW severity floor 4.0 : CVSS 4.5 doit bloquer").isEqualTo("BLOCK");
        assertThat(lowDecision.sourceType()).isEqualTo("PUBLIC_VULN");

        // MEDIUM → nextSeverity=HIGH → plancher=7.0 ; min(7.0, 7.0) = 7.0 (ecosystem maven)
        // CVSS 7.5 >= 7.0 → BLOCK from PUBLIC_VULN
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-medium-floor', 'OSV', 'medium-floor-pkg', 'maven', 'MEDIUM floor test', '["1.0.0"]'::jsonb, 7.5)
                """).update();
        DecisionResult mediumDecision = securityService.getDecision("medium-floor-pkg", "1.0.0", "maven");
        assertThat(mediumDecision.result()).as("MEDIUM severity floor 7.0 : CVSS 7.5 doit bloquer").isEqualTo("BLOCK");
        assertThat(mediumDecision.sourceType()).isEqualTo("PUBLIC_VULN");

        // HIGH → nextSeverity=CRITICAL → plancher=9.0 ; min(9.0, 9.0) = 9.0 (ecosystem npm)
        // CVSS 9.5 >= 9.0 → BLOCK from PUBLIC_VULN
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-high-floor', 'OSV', 'high-floor-pkg', 'npm', 'HIGH floor test', '["1.0.0"]'::jsonb, 9.5)
                """).update();
        DecisionResult highDecision = securityService.getDecision("high-floor-pkg", "1.0.0", "npm");
        assertThat(highDecision.result()).as("HIGH severity floor 9.0 : CVSS 9.5 doit bloquer").isEqualTo("BLOCK");
        assertThat(highDecision.sourceType()).isEqualTo("PUBLIC_VULN");

        // CRITICAL → nextSeverity=null → plancher=11.0 ; min(11.0, 11.0) = 11.0
        // CVSS 10.0 < 11.0 → NOT blocked by the vulnerabilities table
        // The registry does not know "critical-eco" → fail-open ALLOW (REGISTRY_ERROR)
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-critical-floor', 'OSV', 'critical-floor-pkg', 'critical-eco', 'CRITICAL floor test', '["1.0.0"]'::jsonb, 10.0)
                """).update();
        DecisionResult criticalDecision = securityService.getDecision("critical-floor-pkg", "1.0.0", "critical-eco");
        assertThat(criticalDecision.sourceType()).as("CRITICAL severity floor 11.0 : CVSS 10.0 ne doit pas bloquer via PUBLIC_VULN")
                .isNotEqualTo("PUBLIC_VULN");
        assertThat(criticalDecision.result()).isEqualTo("ALLOW");
    }
}
