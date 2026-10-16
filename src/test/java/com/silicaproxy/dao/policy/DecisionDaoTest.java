package com.silicaproxy.dao.policy;/*
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


import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.Verdict;
import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.RangeCandidate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DecisionDaoTest extends BaseIntegrationTest {

    private final DecisionDao decisionDao;
    private final JdbcClient jdbcClient;
    private final JdbcTemplate jdbcTemplate;

    @Autowired
    DecisionDaoTest(DecisionDao decisionDao, JdbcClient jdbcClient, JdbcTemplate jdbcTemplate) {
        this.decisionDao = decisionDao;
        this.jdbcClient = jdbcClient;
        this.jdbcTemplate = jdbcTemplate;
    }

    @BeforeAll
    void setUp() {
        populateData(jdbcClient, jdbcTemplate);
    }

    private static void populateData(JdbcClient jdbcClient, JdbcTemplate jdbcTemplate) {
        // Prior cleaning to avoid collisions in case of multiple executions
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE vulnerability_ingestion_anomalies RESTART IDENTITY CASCADE").update();

        // 1. Insertion of 10,000 internal governance rules
        List<Object[]> policies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            policies.add(new Object[]{
                "policy-package-" + i,
                "npm",
                i + ".x",
                i % 2 == 0 ? "ALLOW" : "BLOCK",
                "Justification " + i,
                "admin-test"
            });
        }
        jdbcTemplate.batchUpdate("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """, policies);

        // 2. Insertion of 500,000 public vulnerabilities
        List<Object[]> vulns = new ArrayList<>();
        for (int i = 0; i < 500000; i++) {
            vulns.add(new Object[]{
                "GHSA-2026-" + i,
                "GITHUB",
                "vuln-package-" + (i % 500),
                "npm",
                "Public vulnerability test " + i,
                "Test details for vulnerability " + i,
                "[\"1.0.0\", \"" + (i % 10) + ".0.0\"]",
                4.0 + (i % 6) // Score entre 4.0 (Medium) et 9.0 (Critical)
            });
        }
        jdbcTemplate.batchUpdate("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?)
            """, vulns);
    }

    @Test
    void shouldPrioritizeCompanyPolicyOverPublicVulnerability() {
        // Register a vulnerability on "test-package"
        // CVSS score 9.5 (Critical)
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
            VALUES ('GHSA-test-1', 'GITHUB', 'test-package', 'npm', 'Critical CVE', 'Details', '["1.0.0"]'::jsonb, 9.5)
            """).update();

        // Register a company_policy rule on "test-package" -> ALLOW
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('test-package', 'npm', '1.0.0', 'ALLOW', 'Explicit authorization', 'security-team')
            """).update();

        // Evaluate the package : the ALLOW rule must win over the critical vulnerability
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("test-package", "1.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.get().reason()).isEqualTo("Explicit authorization");
    }

    @Test
    void shouldBlockPublicVulnerabilityIfCvssAboveThreshold() {
        // Register a vulnerable package without associated governance rule
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
            VALUES ('GHSA-test-2', 'GITHUB', 'vuln-only-package', 'npm', 'Critical CVE', 'Details', '["2.0.0"]'::jsonb, 8.5)
            """).update();

        // Evaluate the package with a threshold of 7.0 : must be blocked
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("vuln-only-package", "2.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.get().reason()).isEqualTo("Critical CVE");
    }

    @Test
    void shouldAllowFromCacheIfSecure() {
        // Register a healthy entry in the API cache
        jdbcClient.sql("""
            INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
            VALUES ('cached-package', 'npm', '3.0.0', true, 'PHYLUM', CURRENT_TIMESTAMP + INTERVAL '1 DAY')
            """).update();

        // Evaluate the package : must be allowed by the cache
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("cached-package", "3.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.API_CACHE);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void shouldBlockRealHistoricallyCompromisedPackageFromFixtureData() {
        // ua-parser-js@0.7.29 is a real documented compromise (cryptominer + trojan).
        // Data inserted directly to avoid depending on @BeforeAll fixture loading order.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('ua-parser-js', 'npm', '0.7.29', 'BLOCK', 'Compromised version containing cryptominer and trojan', 'gitops_sync')
            ON CONFLICT DO NOTHING
            """).update();
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("ua-parser-js", "0.7.29", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldFailClosedOnUnknownPolicyAction() {
        // A policy_action that is not a Verdict name (e.g. a lowercase typo) must block, not allow
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('unknown-action-pkg', 'npm', '1.0.0', 'blacklist', 'Typo in policy file', 'gitops_sync')
            """).update();
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("unknown-action-pkg", "1.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldAlwaysBlockMalwareRegardlessOfCvssThreshold() {
        // Register a malware with ID MAL-xxx and CVSS score 0.0
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
            VALUES ('MAL-test-1', 'OSV', 'malware-package-1', 'npm', 'Malware 1', 'Details', '["1.0.0"]'::jsonb, 0.0)
            """).update();

        // Register a malware with source OPENSSF and CVSS score 0.0
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
            VALUES ('GHSA-test-mal-2', 'OPENSSF', 'malware-package-2', 'npm', 'Malware 2', 'Details', '["1.0.0"]'::jsonb, 0.0)
            """).update();

        // Evaluate with a threshold of 7.0 : both must be blocked despite the CVSS score of 0.0
        Optional<DecisionResult> decision1 = decisionDao.evaluateDecision("malware-package-1", "1.0.0", "npm", 7.0);
        assertThat(decision1).isPresent();
        assertThat(decision1.get().sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN_MALWARE);
        assertThat(decision1.get().result()).isEqualTo(Verdict.BLOCK);

        Optional<DecisionResult> decision2 = decisionDao.evaluateDecision("malware-package-2", "1.0.0", "npm", 7.0);
        assertThat(decision2).isPresent();
        assertThat(decision2.get().sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN_MALWARE);
        assertThat(decision2.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldMeasureDatabaseLatencyUnder20Milliseconds() {
        // Perform 1,000 consecutive queries on random packages to measure performance
        int requestCount = 1000;
        long startTime = System.nanoTime();

        for (int i = 0; i < requestCount; i++) {
            // Query on public vulnerabilities (vuln-package-0 to vuln-package-499)
            String packageName = "vuln-package-" + (i % 500);
            Optional<DecisionResult> decision = decisionDao.evaluateDecision(packageName, "1.0.0", "npm", 7.0);
            // Ensure the query executes properly
            assertThat(decision).isNotNull();
        }

        long endTime = System.nanoTime();
        double durationMs = (endTime - startTime) / 1_000_000.0;
        double averageLatencyMs = durationMs / requestCount;

        System.out.println("Total execution time (DAO Performance) for 1000 queries : " + durationMs + " ms");
        System.out.println("Average latency per query : " + averageLatencyMs + " ms");

        // Performance assertion : average latency lower than 20 milliseconds
        assertThat(averageLatencyMs).isLessThan(20.0);
    }

    @Test
    void shouldPrioritizeCompanyPolicyWhenAllThreeSourcesArePopulated() {
        // Fill the 3 sources for the same package/version
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('multi-source-pkg', 'npm', '1.0.0', 'ALLOW', 'Exception approved', 'security-team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
            VALUES ('GHSA-multi-1', 'GITHUB', 'multi-source-pkg', 'npm', 'Critical flaw', 'Details', '["1.0.0"]'::jsonb, 9.5)
            """).update();
        jdbcClient.sql("""
            INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
            VALUES ('multi-source-pkg', 'npm', '1.0.0', false, 'OSV_LIVE', CURRENT_TIMESTAMP + INTERVAL '1 DAY')
            """).update();

        // Corporate policy (priority 1) must override the vulnerability (priority 2) and the cache (priority 3)
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("multi-source-pkg", "1.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.get().reason()).isEqualTo("Exception approved");
    }

    @Test
    void shouldPreferExactVersionBlacklistOverWildcardWhitelist() {
        // Two company_policy rules coexist : * (stored pre-translated as %) → ALLOW and
        // 1.0.0 → BLOCK. The most specific rule (exact version) must always win.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('exact-beats-wildcard-pkg', 'npm', '%', 'ALLOW', 'Global authorization', 'team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('exact-beats-wildcard-pkg', 'npm', '1.0.0', 'BLOCK', 'Compromised version', 'security-team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("exact-beats-wildcard-pkg", "1.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldPreferBlacklistOverWhitelistAtEqualSpecificity() {
        // Two DIFFERENT wildcard version_pattern values (so the unique index on
        // (package_name, ecosystem, version_pattern) is not violated), both non-exact matches
        // for the requested version -- so both get the same specificity (exact package + non-
        // exact version = 1) even though one pattern is narrower than the other. The most
        // restrictive result must win deterministically, not whichever row the DB returns first.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('tie-break-pkg', 'npm', '4.%', 'ALLOW', 'Approved', 'team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('tie-break-pkg', 'npm', '%', 'BLOCK', 'Actually compromised', 'security-team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("tie-break-pkg", "4.17.21", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldApplyWildcardWhitelistForOtherVersionsWhenExactMatchAbsent() {
        // The rule * (stored pre-translated as %) → ALLOW applies for versions without a
        // corresponding exact rule.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('wildcard-win-pkg', 'npm', '%', 'ALLOW', 'Global authorization', 'team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('wildcard-win-pkg', 'npm', '1.0.0', 'BLOCK', 'Compromised version', 'security-team')
            """).update();

        // 2.0.0 has no exact rule → the wildcard rule * → ALLOW applies
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("wildcard-win-pkg", "2.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void shouldApplyXWildcardPatternForVersions() {
        // version_pattern is always pre-translated by GitOpsSyncService at write time (a GitOps
        // rule version of '4.x' is stored here already as '4.%') -- this test inserts that
        // translated form directly to simulate the real write path, bypassing GitOpsSyncService.
        // '4.17.21' must match the stored '4.%' pattern via a plain LIKE.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('x-wildcard-pkg', 'npm', '4.%', 'ALLOW', 'Series 4 approved', 'team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("x-wildcard-pkg", "4.17.21", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void shouldTreatUnderscoreInVersionPatternAsLiteral() {
        // '_' is a single-character wildcard in SQL LIKE : a rule for "1.0.0_rc1" must not
        // also match "1.0.0-rc1" (or "1.0.01rc1"), which would let an unvetted version ride on
        // a ALLOW rule and bypass the public vulnerability check below it.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('underscore-version-pkg', 'maven', '1.0.0_rc1', 'ALLOW', 'rc1 approved', 'team')
            """).update();

        assertThat(decisionDao.evaluateDecision("underscore-version-pkg", "1.0.0-rc1", "maven", 7.0)).isEmpty();
        assertThat(decisionDao.evaluateDecision("underscore-version-pkg", "1.0.01rc1", "maven", 7.0)).isEmpty();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("underscore-version-pkg", "1.0.0_rc1", "maven", 7.0);
        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void shouldKeepExactSpecificityForVersionContainingUnderscore() {
        // Escaping '_' must not cost an exact "1.0.0_rc1" rule its exact-version specificity :
        // it still has to beat a wildcard rule for the same package.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('underscore-exact-pkg', 'maven', '%', 'ALLOW', 'Global authorization', 'team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('underscore-exact-pkg', 'maven', '1.0.0_rc1', 'BLOCK', 'Compromised rc', 'security-team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("underscore-exact-pkg", "1.0.0_rc1", "maven", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldBlockViaAnomalyMatchWhenSuspiciousVersionMatchesRequestedPackage() {
        // Mirrors the real gradio case: package_name/ecosystem on the anomaly row reflect
        // the WRONG outer advisory ("gradio"/pypi) -- only suspicious_version carries the
        // real embedded identifier of the actual requested package ("@gradio/chatbot", npm).
        jdbcClient.sql("""
            INSERT INTO vulnerability_ingestion_anomalies
                (vulnerability_id, source, package_name, ecosystem, suspicious_version, cvss_score)
            VALUES ('PYSEC-mock', 'OSV', 'gradio', 'pypi', '@gradio/chatbot@0.4.2', 8.1)
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("@gradio/chatbot", "0.4.2", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.PUBLIC_VULN_ANOMALY);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
    }

    @Test
    void shouldNotBlockAnomalyMatchWhenBelowCvssThreshold() {
        jdbcClient.sql("""
            INSERT INTO vulnerability_ingestion_anomalies
                (vulnerability_id, source, package_name, ecosystem, suspicious_version, cvss_score)
            VALUES ('PYSEC-mock-low', 'OSV', 'gradio', 'pypi', '@gradio/low-severity@1.0.0', 3.0)
            """).update();

        Optional<DecisionResult> decision =
                decisionDao.evaluateDecision("@gradio/low-severity", "1.0.0", "npm", 7.0);

        assertThat(decision).isEmpty();
    }

    @Test
    void shouldPrioritizeCompanyPolicyOverAnomalyMatch() {
        jdbcClient.sql("""
            INSERT INTO vulnerability_ingestion_anomalies
                (vulnerability_id, source, package_name, ecosystem, suspicious_version, cvss_score)
            VALUES ('PYSEC-mock-override', 'OSV', 'gradio', 'pypi', '@gradio/approved-fork@2.0.0', 9.0)
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('@gradio/approved-fork', 'npm', '2.0.0', 'ALLOW', 'Reviewed and approved fork', 'security-team')
            """).update();

        Optional<DecisionResult> decision =
                decisionDao.evaluateDecision("@gradio/approved-fork", "2.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.ALLOW);
    }

    @Test
    void shouldNotMatchXWildcardPatternForDifferentMajor() {
        // Stored (already-translated) pattern '4.%' must not match '3.0.0'.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('x-wildcard-no-match-pkg', 'npm', '4.%', 'ALLOW', 'Series 4 only', 'team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("x-wildcard-no-match-pkg", "3.0.0", "npm", 7.0);

        assertThat(decision).isEmpty();
    }

    @Test
    void shouldReturnRangeCandidatesAboveTheCvssFloorOrMalware() {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, affected_ranges, cvss_score)
            VALUES
              ('GHSA-range-high', 'OSV', 'range-pkg', 'npm', 'High', '[]'::jsonb,
               '[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]'::jsonb, 9.0),
              ('GHSA-range-low', 'OSV', 'range-pkg', 'npm', 'Low', '[]'::jsonb,
               '[{"type":"SEMVER","events":[{"introduced":"0"}]}]'::jsonb, 3.0),
              ('MAL-range-0001', 'OSV', 'range-pkg', 'npm', 'Malware', '[]'::jsonb,
               '[{"type":"SEMVER","events":[{"introduced":"0"}]}]'::jsonb, 0.0),
              ('GHSA-range-none', 'OSV', 'range-pkg', 'npm', 'Versions only', '["1.0.0"]'::jsonb,
               '[]'::jsonb, 9.0)
            """).update();

        List<RangeCandidate> candidates = decisionDao.findRangeCandidates("range-pkg", "npm", 7.0);

        assertThat(candidates).extracting(RangeCandidate::id)
                .containsExactlyInAnyOrder("GHSA-range-high", "MAL-range-0001");
        assertThat(candidates).filteredOn(c -> c.id().equals("GHSA-range-high")).singleElement()
                .satisfies(c -> assertThat(c.rangesJson()).contains("2.0.0"));
    }
}
