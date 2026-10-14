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


package com.silicaproxy.performance;

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;

// EXPLAIN-based guards : each test checks that a hot query is served by the index created for it.
// The public_vulnerabilities checks run on a seeded, VACUUM ANALYZEd table : on an empty,
// never-analyzed table the planner estimates 1 row for every index and simply picks the last
// one created (that is how idx_public_vuln_ecosystem, V16, made the old check flaky), which
// says nothing about production plans.
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DatabaseIndexUtilizationTest extends BaseIntegrationTest {

    // Seed rows are tagged by id so @AfterAll removes exactly them : the database is shared
    // with every other test class (VulnerabilitySyncControllerTest / MonitoringIntegrationTest
    // read countByEcosystem()).
    private static final String SEED_ID_PREFIX = "IDXTEST-";

    private final JdbcClient jdbcClient;
    private final JdbcTemplate jdbcTemplate;

    @Autowired
    DatabaseIndexUtilizationTest(JdbcClient jdbcClient, JdbcTemplate jdbcTemplate) {
        this.jdbcClient = jdbcClient;
        this.jdbcTemplate = jdbcTemplate;
    }

    @BeforeAll
    void seedPublicVulnerabilities() {
        // ~100k advisories over ~30k packages and 4 ecosystems (a few advisories per package,
        // as in a real OSV mirror) ; details padding keeps the heap wide like production
        // (~280 MB), so a Seq Scan is not artificially cheap.
        jdbcTemplate.update("""
                INSERT INTO public_vulnerabilities
                    (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
                SELECT ? || g, 'OSV', 'idx-pkg-' || (g % 30000),
                       (ARRAY['npm', 'pypi', 'maven', 'go'])[1 + g % 4],
                       'seeded advisory', repeat('x', 500), '["1.0.0"]'::jsonb, (g % 100) / 10.0
                FROM generate_series(1, 100000) AS g
                """, SEED_ID_PREFIX);
        jdbcTemplate.update("""
                INSERT INTO public_vulnerabilities
                    (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
                VALUES (? || 'lodash-1', 'OSV', 'lodash', 'npm', 'Prototype pollution', 'd',
                        '["4.17.20"]'::jsonb, 7.4),
                       (? || 'lodash-2', 'OSV', 'lodash', 'npm', 'Command injection', 'd',
                        '["4.17.20"]'::jsonb, 7.2)
                """, SEED_ID_PREFIX, SEED_ID_PREFIX);
        // VACUUM (not only ANALYZE) : the Index Only Scan expected for countByEcosystem needs an
        // up-to-date visibility map. Runs outside any transaction through JdbcTemplate.
        vacuumUntilAllVisible();
    }

    // A VACUUM issued while another session (e.g. an application startup job) still holds an
    // older snapshot cannot mark the freshly inserted pages all-visible, leaving relallvisible
    // at 0 and making the planner fall back to a Seq Scan. Retry until the visibility map is set.
    private void vacuumUntilAllVisible() {
        for (int attempt = 0; attempt < 20; attempt++) {
            jdbcTemplate.execute("VACUUM ANALYZE public_vulnerabilities");
            Boolean allVisible = jdbcClient.sql("""
                    SELECT relallvisible >= relpages * 0.95
                    FROM pg_class WHERE relname = 'public_vulnerabilities'
                    """).query(Boolean.class).single();
            if (Boolean.TRUE.equals(allVisible)) {
                return;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        throw new IllegalStateException("VACUUM could not mark public_vulnerabilities all-visible");
    }

    @AfterAll
    void removeSeededPublicVulnerabilities() {
        jdbcTemplate.update("DELETE FROM public_vulnerabilities WHERE id LIKE ? || '%'", SEED_ID_PREFIX);
        jdbcTemplate.execute("VACUUM ANALYZE public_vulnerabilities");
    }

    // DecisionDao.evaluateDecision(), PRIORITY 2 block (same predicate, malware clause included) :
    // must be served by idx_public_vuln_search (package_name, ecosystem), V1.
    @Test
    void decisionQueryUsesPackageEcosystemIndex() {
        String plan = explain("""
                SELECT 2 AS priority, 0 AS specificity,
                       CASE WHEN id LIKE 'MAL-%' OR source = 'OPENSSF' THEN 'PUBLIC_VULN_MALWARE'
                            ELSE 'PUBLIC_VULN' END AS source_type,
                       'BLOCK' AS result, summary AS reason
                FROM public_vulnerabilities
                WHERE package_name = 'lodash'
                  AND ecosystem = 'npm'
                  AND affected_versions @> jsonb_build_array('4.17.20')
                  AND (cvss_score >= 7.0 OR id LIKE 'MAL-%' OR source = 'OPENSSF')
                """);

        assertThat(plan).contains("idx_public_vuln_search");
        assertThat(plan).doesNotContain("Seq Scan");
    }

    // PackageSearchDao.buildVulnSpec() without the optional ecosystem filter : only package_name
    // is constrained, so it must stay the leading column of idx_public_vuln_search.
    @Test
    void packageSearchWithoutEcosystemUsesPackageIndex() {
        String plan = explain("""
                SELECT pv.id, pv.source, pv.package_name AS package_name, pv.ecosystem, pv.summary,
                       pv.cvss_score, pv.published_at, array_agg(elem.value) AS matched_versions
                FROM public_vulnerabilities pv
                CROSS JOIN LATERAL jsonb_array_elements_text(pv.affected_versions) AS elem(value)
                WHERE pv.package_name = 'lodash'
                GROUP BY pv.id, pv.source, pv.package_name, pv.ecosystem, pv.summary, pv.cvss_score, pv.published_at
                """);

        assertThat(plan).contains("idx_public_vuln_search");
        assertThat(plan).doesNotContain("Seq Scan");
    }

    // VulnerabilityDao.countByEcosystem() (GET /api/vulnerabilities/sync/status) : V16 added
    // idx_public_vuln_ecosystem precisely so this GROUP BY reads the small index instead of
    // sequentially scanning the whole table (~4 s in production).
    @Test
    void countByEcosystemUsesIndexOnlyScan() {
        String plan = explain(
                "SELECT ecosystem, count(*) AS cnt FROM public_vulnerabilities GROUP BY ecosystem ORDER BY ecosystem");

        assertThat(plan).contains("idx_public_vuln_ecosystem");
        assertThat(plan).contains("Index Only Scan");
        assertThat(plan).doesNotContain("Seq Scan");
    }

    private String explain(String sql) {
        return jdbcClient.sql("EXPLAIN (FORMAT JSON) " + sql).query(String.class).single();
    }

    // ExternalValidationVerdictsDao.findAllByPackage() filters by (package_name, ecosystem,
    // package_version) without service_name — the older idx_ext_verdicts_lookup index has
    // service_name as its leftmost column so it can't serve this query. Confirms
    // idx_ext_verdicts_by_package (V9 migration) is actually used instead of a seq scan.
    @Test
    void shouldUtilizeCoveringIndexForExternalValidationVerdictsByPackage() {
        String explainSql = """
                EXPLAIN (FORMAT JSON)
                SELECT id, service_name, package_name, ecosystem, package_version, reason, created_at
                FROM external_validation_verdicts
                WHERE package_name    = 'lodash'
                  AND ecosystem       = 'npm'
                  AND package_version = '4.17.21'
                """;

        String explainResult = jdbcClient.sql(explainSql).query(String.class).single();

        assertThat(explainResult).contains("idx_ext_verdicts_by_package");
        assertThat(explainResult).contains("Index Scan");
    }
}
