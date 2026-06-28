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


import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.model.dto.DecisionResult;
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

        // 1. Insertion of 10,000 internal governance rules
        List<Object[]> policies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            policies.add(new Object[]{
                "policy-package-" + i,
                "npm",
                i + ".x",
                i % 2 == 0 ? "WHITELIST" : "BLACKLIST",
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

        // Register a company_policy rule on "test-package" -> WHITELIST
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('test-package', 'npm', '1.0.0', 'WHITELIST', 'Explicit authorization', 'security-team')
            """).update();

        // Evaluate the package : the WHITELIST rule must win over the critical vulnerability
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("test-package", "1.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(decision.get().result()).isEqualTo("WHITELIST");
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
        assertThat(decision.get().sourceType()).isEqualTo("PUBLIC_VULN");
        assertThat(decision.get().result()).isEqualTo("BLOCK");
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
        assertThat(decision.get().sourceType()).isEqualTo("API_CACHE");
        assertThat(decision.get().result()).isEqualTo("ALLOW");
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
        assertThat(decision.get().sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(decision.get().result()).isEqualTo("BLOCK");
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
        assertThat(decision1.get().sourceType()).isEqualTo("PUBLIC_VULN");
        assertThat(decision1.get().result()).isEqualTo("BLOCK");

        Optional<DecisionResult> decision2 = decisionDao.evaluateDecision("malware-package-2", "1.0.0", "npm", 7.0);
        assertThat(decision2).isPresent();
        assertThat(decision2.get().sourceType()).isEqualTo("PUBLIC_VULN");
        assertThat(decision2.get().result()).isEqualTo("BLOCK");
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
            VALUES ('multi-source-pkg', 'npm', '1.0.0', 'WHITELIST', 'Exception approved', 'security-team')
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
        assertThat(decision.get().sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(decision.get().result()).isEqualTo("WHITELIST");
        assertThat(decision.get().reason()).isEqualTo("Exception approved");
    }

    @Test
    void shouldPreferExactVersionBlacklistOverWildcardWhitelist() {
        // Two company_policy rules coexist : * → WHITELIST and 1.0.0 → BLACKLIST
        // The most specific rule (exact version) must always win.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('exact-beats-wildcard-pkg', 'npm', '*', 'WHITELIST', 'Global authorization', 'team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('exact-beats-wildcard-pkg', 'npm', '1.0.0', 'BLACKLIST', 'Compromised version', 'security-team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("exact-beats-wildcard-pkg", "1.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(decision.get().result()).isEqualTo("BLACKLIST");
    }

    @Test
    void shouldApplyWildcardWhitelistForOtherVersionsWhenExactMatchAbsent() {
        // The rule * → WHITELIST applies for versions without corresponding exact rule.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('wildcard-win-pkg', 'npm', '*', 'WHITELIST', 'Global authorization', 'team')
            """).update();
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('wildcard-win-pkg', 'npm', '1.0.0', 'BLACKLIST', 'Compromised version', 'security-team')
            """).update();

        // 2.0.0 has no exact rule → the wildcard rule * → WHITELIST applies
        Optional<DecisionResult> decision = decisionDao.evaluateDecision("wildcard-win-pkg", "2.0.0", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(decision.get().result()).isEqualTo("WHITELIST");
    }

    @Test
    void shouldApplyXWildcardPatternForVersions() {
        // SQL translates 'x' to '%' via REPLACE : '4.x' becomes '4.%', so '4.17.21' must match.
        // If the translation is broken, GitOps policies using '4.x' do not apply.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('x-wildcard-pkg', 'npm', '4.x', 'WHITELIST', 'Series 4 approved', 'team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("x-wildcard-pkg", "4.17.21", "npm", 7.0);

        assertThat(decision).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(decision.get().result()).isEqualTo("WHITELIST");
    }

    @Test
    void shouldNotMatchXWildcardPatternForDifferentMajor() {
        // '4.x' must not match '3.0.0' : the SQL translation '4.%' correctly excludes other series.
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('x-wildcard-no-match-pkg', 'npm', '4.x', 'WHITELIST', 'Series 4 only', 'team')
            """).update();

        Optional<DecisionResult> decision = decisionDao.evaluateDecision("x-wildcard-no-match-pkg", "3.0.0", "npm", 7.0);

        assertThat(decision).isEmpty();
    }
}
