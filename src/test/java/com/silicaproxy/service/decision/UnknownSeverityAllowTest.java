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
import com.silicaproxy.dao.vulnerability.VulnerabilityDao;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.Verdict;
import com.silicaproxy.service.vulnerability.VulnerabilityIngestionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/** unknown-severity-action=ALLOW : an advisory with no score anywhere no longer blocks. */
@TestPropertySource(properties = "silicaproxy.severity-threshold.unknown-severity-action=ALLOW")
class UnknownSeverityAllowTest extends BaseIntegrationTest {

    private final VulnerabilityIngestionService ingestionService;
    private final VulnerabilityDao vulnerabilityDao;
    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    UnknownSeverityAllowTest(VulnerabilityIngestionService ingestionService, VulnerabilityDao vulnerabilityDao,
            SecurityService securityService, JdbcClient jdbcClient) {
        this.ingestionService = ingestionService;
        this.vulnerabilityDao = vulnerabilityDao;
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    @Test
    void orphanAdvisoryShouldBeAllowedWhenConfigured() throws Exception {
        UnknownSeverityDecisionTest.ingest(ingestionService, vulnerabilityDao,
                UnknownSeverityDecisionTest.pysec("PYSEC-2099-3", "orphan-allowed-pkg", "1.0.0", "\"CVE-2099-3\""));

        DecisionResult decision = securityService.getDecision("orphan-allowed-pkg", "1.0.0", "pypi", "");
        assertThat(decision.sourceType()).isNotEqualTo(DecisionSource.PUBLIC_VULN);
        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void malwareShouldStillBeBlocked() throws Exception {
        UnknownSeverityDecisionTest.ingest(ingestionService, vulnerabilityDao,
                UnknownSeverityDecisionTest.pysec("MAL-2099-1", "evil-pkg", "1.0.0", ""));

        DecisionResult decision = securityService.getDecision("evil-pkg", "1.0.0", "pypi", "");
        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN_MALWARE);
    }
}
