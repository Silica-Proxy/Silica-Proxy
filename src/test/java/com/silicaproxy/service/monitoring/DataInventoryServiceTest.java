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


package com.silicaproxy.service.monitoring;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.service.monitoring.DataInventoryService.DataInventory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;

class DataInventoryServiceTest extends BaseIntegrationTest {

    private final DataInventoryService dataInventoryService;
    private final JdbcClient jdbcClient;

    @Autowired
    DataInventoryServiceTest(DataInventoryService dataInventoryService, JdbcClient jdbcClient) {
        this.dataInventoryService = dataInventoryService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldReturnZeroInventoryWhenTablesAreEmpty() {
        DataInventory inventory = dataInventoryService.getInventory();

        assertThat(inventory.totalVulnerabilities()).isZero();
        assertThat(inventory.vulnerabilitiesByEcosystem()).isEmpty();
        assertThat(inventory.totalPolicies()).isZero();
        assertThat(inventory.policiesByEcosystem()).isEmpty();
    }

    @Test
    void shouldAggregateCountsByEcosystem() {
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-1', 'OSV', 'pkg-a', 'npm', 'Bug', '["1.0.0"]'::jsonb, 7.0)
                """).update();
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-2', 'OSV', 'pkg-b', 'npm', 'Bug', '["1.0.0"]'::jsonb, 7.0)
                """).update();
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-3', 'OSV', 'pkg-c', 'pypi', 'Bug', '["1.0.0"]'::jsonb, 7.0)
                """).update();

        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '*', 'WHITELIST', 'Approved', 'admin')
                """).update();

        DataInventory inventory = dataInventoryService.getInventory();

        assertThat(inventory.totalVulnerabilities()).isEqualTo(3L);
        assertThat(inventory.vulnerabilitiesByEcosystem()).containsEntry("npm", 2L).containsEntry("pypi", 1L);
        assertThat(inventory.totalPolicies()).isEqualTo(1L);
        assertThat(inventory.policiesByEcosystem()).containsEntry("npm", 1L);
    }
}
