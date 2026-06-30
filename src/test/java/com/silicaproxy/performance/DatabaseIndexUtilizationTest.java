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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;

class DatabaseIndexUtilizationTest extends BaseIntegrationTest {

    private final JdbcClient jdbcClient;

    @Autowired
    DatabaseIndexUtilizationTest(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Test
    void shouldUtilizeCoveringIndexForPublicVulnerabilities() {
        // Run EXPLAIN on the public_vulnerabilities part of the query
        String explainSql = """
                EXPLAIN (FORMAT JSON)
                SELECT 2 AS priority, 'PUBLIC_VULN' AS source_type, 'BLOCK' AS result, summary AS reason
                FROM public_vulnerabilities
                WHERE package_name = 'lodash'
                  AND ecosystem = 'npm'
                  AND affected_versions @> jsonb_build_array('4.17.20')
                  AND cvss_score >= 7.0
                """;

        String explainResult = jdbcClient.sql(explainSql).query(String.class).single();

        assertThat(explainResult).contains("idx_public_vuln_search");
        assertThat(explainResult).contains("Index Scan");
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
