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
import com.silicaproxy.model.dto.OsvParseResult;
import com.silicaproxy.model.dto.Verdict;
import com.silicaproxy.service.vulnerability.VulnerabilityIngestionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Local decision on PyPI advisories that carry no score of their own (PYSEC), through the real
 * ingestion pipeline : parse, upsert, score inheritance, decision. pypi threshold of the test
 * profile : max-allowed-severity MEDIUM, max-allowed-cvss 7.0 ; unknown-severity-action BLOCK.
 */
class UnknownSeverityDecisionTest extends BaseIntegrationTest {

    static final String CRITICAL_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    private final VulnerabilityIngestionService ingestionService;
    private final VulnerabilityDao vulnerabilityDao;
    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    UnknownSeverityDecisionTest(VulnerabilityIngestionService ingestionService, VulnerabilityDao vulnerabilityDao,
            SecurityService securityService, JdbcClient jdbcClient) {
        this.ingestionService = ingestionService;
        this.vulnerabilityDao = vulnerabilityDao;
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

    static void ingest(VulnerabilityIngestionService ingestionService, VulnerabilityDao vulnerabilityDao,
            String... advisories) throws Exception {
        for (String advisory : advisories) {
            OsvParseResult parsed = ingestionService.parseOsvJson("pypi", advisory);
            vulnerabilityDao.replaceAdvisories("pypi", parsed.advisoryIds(), parsed.upserts(), parsed.anomalies());
        }
        vulnerabilityDao.refreshInheritedScores("pypi");
    }

    static String pysec(String id, String pypiName, String version, String aliases) {
        return """
                {"id": "%s", "aliases": [%s], "summary": "%s",
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "%s"}, "versions": ["%s"]}]}
                """.formatted(id, aliases, id, pypiName, version);
    }

    static String ghsa(String id, String pypiName, String version, String aliases, String severityFields) {
        return """
                {"id": "%s", "aliases": [%s], "summary": "%s", %s,
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "%s"}, "versions": ["%s"]}]}
                """.formatted(id, aliases, id, severityFields, pypiName, version);
    }

    @Test
    void unscoredPysecShouldInheritCriticalScoreOfItsGhsaAlias() throws Exception {
        // PyYAML case : PYSEC-2021-142 has no severity, GHSA-8q59-q68h-6hv4 (same flaw) is 9.8.
        // The GHSA advisory lists another version here so that only the PYSEC row matches 5.3.
        ingest(ingestionService, vulnerabilityDao,
                pysec("PYSEC-2021-142", "PyYAML", "5.3", "\"CVE-2020-14343\", \"GHSA-8q59-q68h-6hv4\""),
                ghsa("GHSA-8q59-q68h-6hv4", "PyYAML", "5.1", "\"CVE-2020-14343\"",
                        "\"severity\": [{\"type\": \"CVSS_V3\", \"score\": \"" + CRITICAL_V3 + "\"}]"));

        // Stored under the PEP 503 name, inherited score set
        assertThat(jdbcClient.sql("""
                SELECT inherited_cvss_score FROM public_vulnerabilities WHERE id = 'PYSEC-2021-142' AND package_name = 'pyyaml'
                """).query(Double.class).single()).isEqualTo(9.8);

        DecisionResult decision = securityService.getDecision("pyyaml", "5.3", "pypi", "");
        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN);
    }

    @Test
    void unscoredPysecShouldBeAllowedWhenItsGhsaAliasIsModerate() throws Exception {
        // Linked through the common CVE id only ; GHSA carries a qualitative MODERATE (4.0)
        ingest(ingestionService, vulnerabilityDao,
                pysec("PYSEC-2099-1", "moderate-pkg", "1.0.0", "\"CVE-2099-1\""),
                ghsa("GHSA-mmmm-mmmm-mmmm", "moderate-pkg", "0.9.0", "\"CVE-2099-1\"",
                        "\"database_specific\": {\"severity\": \"MODERATE\"}"));

        DecisionResult decision = securityService.getDecision("moderate-pkg", "1.0.0", "pypi", "");
        assertThat(decision.sourceType()).isNotEqualTo(DecisionSource.PUBLIC_VULN);
        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void orphanAdvisoryWithoutAnyScoreShouldBeBlockedByDefault() throws Exception {
        ingest(ingestionService, vulnerabilityDao, pysec("PYSEC-2099-2", "orphan-pkg", "1.0.0", "\"CVE-2099-2\""));

        assertThat(jdbcClient.sql("""
                SELECT count(*) FROM public_vulnerabilities
                WHERE id = 'PYSEC-2099-2' AND cvss_score IS NULL AND inherited_cvss_score IS NULL
                """).query(Long.class).single()).isEqualTo(1L);
        DecisionResult decision = securityService.getDecision("orphan-pkg", "1.0.0", "pypi", "");
        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN);
    }

    @Test
    void qualitativeOnlyHighAdvisoryShouldBeBlocked() throws Exception {
        // HIGH -> 7.0, the lower bound of the first level above max-allowed-severity MEDIUM
        ingest(ingestionService, vulnerabilityDao, ghsa("GHSA-hhhh-hhhh-hhhh", "Typing_Extensions", "4.0.0", "",
                "\"database_specific\": {\"severity\": \"HIGH\"}"));

        DecisionResult decision = securityService.getDecision("typing-extensions", "4.0.0", "pypi", "");
        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN);
    }
}
