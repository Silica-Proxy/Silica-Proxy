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
import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.model.dto.AdvisoryFinding;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.SeverityThreshold;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The "Severity and CVSS thresholds" table of the README, checked on both paths a package can be
 * judged by : an advisory of the local tables (DecisionDao) and an advisory reported by the live
 * OSV API (SeverityPolicy). Both must give the same verdict for the same score and threshold.
 */
@TestPropertySource(properties = {
        "silicaproxy.severity-threshold.ecosystems.critical-7.max-allowed-severity=CRITICAL",
        "silicaproxy.severity-threshold.ecosystems.critical-7.max-allowed-cvss=7.0",
        "silicaproxy.severity-threshold.ecosystems.medium-9.max-allowed-severity=MEDIUM",
        "silicaproxy.severity-threshold.ecosystems.medium-9.max-allowed-cvss=9.0",
        "silicaproxy.severity-threshold.ecosystems.critical-9.max-allowed-severity=CRITICAL",
        "silicaproxy.severity-threshold.ecosystems.critical-9.max-allowed-cvss=9.0"
})
class SeverityThresholdScenariosTest extends BaseIntegrationTest {

    private final SeverityPolicy severityPolicy;
    private final DecisionDao decisionDao;
    private final JdbcClient jdbcClient;

    @Autowired
    SeverityThresholdScenariosTest(SeverityPolicy severityPolicy, DecisionDao decisionDao, JdbcClient jdbcClient) {
        this.severityPolicy = severityPolicy;
        this.decisionDao = decisionDao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
    }

    @ParameterizedTest(name = "CVSS {1} on {0} : blocked={2}")
    @CsvSource({
            // README : HIGH severity, CVSS 8.5, max CRITICAL / 7.0 -> BLOCK (CVSS > 7.0)
            "critical-7, 8.5, true",
            // README : HIGH severity, CVSS 6.5, max CRITICAL / 7.0 -> ALLOW
            "critical-7, 6.5, false",
            // max-allowed-cvss is itself allowed : "blocks CVSS > 7.0"
            "critical-7, 7.0, false",
            // README : max MEDIUM -> blocked from the HIGH lower bound (7.0), whatever max-allowed-cvss
            "medium-9, 7.5, true",
            "medium-9, 7.0, true",
            "medium-9, 6.9, false",
            // README : CRITICAL severity, CVSS 8.5, max CRITICAL / 9.0 -> ALLOW
            "critical-9, 8.5, false",
            "critical-9, 9.1, true"
    })
    void localAndLiveAdvisoriesShouldGetTheSameVerdict(String ecosystem, double cvss, boolean blocked) {
        SeverityThreshold threshold = severityPolicy.thresholdFor(ecosystem);

        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('GHSA-scenario', 'OSV', 'scenario-pkg', :ecosystem, 'scenario', '["1.0.0"]'::jsonb, :cvss)
                """).param("ecosystem", ecosystem).param("cvss", cvss).update();
        Optional<DecisionResult> local = decisionDao.evaluateDecision("scenario-pkg", "1.0.0", ecosystem, threshold);
        ApiCheckResult live = severityPolicy.apply(ApiCheckResult.ofFindings(200, 1,
                List.of(new AdvisoryFinding("GHSA-scenario", List.of(), cvss))), threshold);

        assertThat(local.map(DecisionResult::sourceType)).isEqualTo(
                blocked ? Optional.of(DecisionSource.PUBLIC_VULN) : Optional.empty());
        assertThat(live.vulnerable()).isEqualTo(blocked);
    }
}
