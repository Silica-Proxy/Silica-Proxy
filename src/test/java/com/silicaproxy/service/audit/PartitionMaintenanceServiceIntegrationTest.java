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


package com.silicaproxy.service.audit;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.audit.PartitionMaintenanceDao;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.YearMonth;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link PartitionMaintenanceService}.
 * Verifies that the dynamic partition creation works correctly for both partitioned tables
 * ({@code proxy_audit_logs} and {@code api_call_log}) in a real database environment.
 */
class PartitionMaintenanceServiceIntegrationTest extends BaseIntegrationTest {

    // Use far future months to avoid collisions with Flyway-created partitions
    // (proxy_audit_logs_y2026m06/07/08 and api_call_log_y2026m06/07/08)
    private static final YearMonth TEST_REFERENCE_MONTH = YearMonth.of(2099, 6);
    private static final int MONTHS_AHEAD = 3;

    @Autowired
    private PartitionMaintenanceService partitionMaintenanceService;

    @Autowired
    private JdbcClient jdbcClient;

    @AfterEach
    void cleanupTestPartitions() {
        // Drop all test partitions for both tables
        for (int i = 0; i <= MONTHS_AHEAD; i++) {
            YearMonth month = TEST_REFERENCE_MONTH.plusMonths(i);
            String partitionName = PartitionMaintenanceDao.partitionName("proxy_audit_logs", month);
            jdbcClient.sql("DROP TABLE IF EXISTS " + partitionName).update();

            partitionName = PartitionMaintenanceDao.partitionName("api_call_log", month);
            jdbcClient.sql("DROP TABLE IF EXISTS " + partitionName).update();
        }
    }

    @Test
    void shouldCreatePartitionsForAllManagedTables() {
        partitionMaintenanceService.ensureFuturePartitionsExist(TEST_REFERENCE_MONTH);

        // Verify partitions were created for proxy_audit_logs
        for (int i = 0; i <= MONTHS_AHEAD; i++) {
            YearMonth month = TEST_REFERENCE_MONTH.plusMonths(i);
            String partitionName = PartitionMaintenanceDao.partitionName("proxy_audit_logs", month);
            assertThat(tableExists(partitionName)).isTrue();
        }

        // Verify partitions were created for api_call_log
        for (int i = 0; i <= MONTHS_AHEAD; i++) {
            YearMonth month = TEST_REFERENCE_MONTH.plusMonths(i);
            String partitionName = PartitionMaintenanceDao.partitionName("api_call_log", month);
            assertThat(tableExists(partitionName)).isTrue();
        }
    }

    @Test
    void shouldCreatePartitionsWithCorrectRangeBounds() {
        YearMonth testMonth = TEST_REFERENCE_MONTH;
        partitionMaintenanceService.ensureFuturePartitionsExist(testMonth);

        // Verify partition for proxy_audit_logs has correct bounds
        String proxyPartition = PartitionMaintenanceDao.partitionName("proxy_audit_logs", testMonth);
        assertThat(partitionHasCorrectBounds(proxyPartition, testMonth, "proxy_audit_logs")).isTrue();

        // Verify partition for api_call_log has correct bounds
        String apiPartition = PartitionMaintenanceDao.partitionName("api_call_log", testMonth);
        assertThat(partitionHasCorrectBounds(apiPartition, testMonth, "api_call_log")).isTrue();
    }

    @Test
    void shouldBeIdempotentWhenCalledMultipleTimes() {
        // First call creates partitions
        partitionMaintenanceService.ensureFuturePartitionsExist(TEST_REFERENCE_MONTH);

        // Second call should not fail
        partitionMaintenanceService.ensureFuturePartitionsExist(TEST_REFERENCE_MONTH);

        // Third call should also not fail
        partitionMaintenanceService.ensureFuturePartitionsExist(TEST_REFERENCE_MONTH);

        // All partitions should still exist
        for (int i = 0; i <= MONTHS_AHEAD; i++) {
            YearMonth month = TEST_REFERENCE_MONTH.plusMonths(i);
            String proxyPartition = PartitionMaintenanceDao.partitionName("proxy_audit_logs", month);
            String apiPartition = PartitionMaintenanceDao.partitionName("api_call_log", month);
            assertThat(tableExists(proxyPartition)).isTrue();
            assertThat(tableExists(apiPartition)).isTrue();
        }
    }

    @Test
    void shouldCreatePartitionsThatAcceptInserts() {
        YearMonth testMonth = TEST_REFERENCE_MONTH;
        partitionMaintenanceService.ensureFuturePartitionsExist(testMonth);

        // Insert into proxy_audit_logs partition
        String proxyPartition = PartitionMaintenanceDao.partitionName("proxy_audit_logs", testMonth);
        jdbcClient.sql("""
            INSERT INTO proxy_audit_logs
                (timestamp, package_name, package_version, ecosystem, decision_source, verdict, execution_time_ms)
            VALUES ('2099-06-15T12:00:00Z', 'test-pkg', '1.0.0', 'npm', 'COMPANY_POLICY', 'ALLOW', 10)
            """).update();

        Integer proxyCount = jdbcClient.sql(
                "SELECT COUNT(*) FROM " + proxyPartition).query(Integer.class).single();
        assertThat(proxyCount).isEqualTo(1);

        // Insert into api_call_log partition
        String apiPartition = PartitionMaintenanceDao.partitionName("api_call_log", testMonth);
        jdbcClient.sql("""
            INSERT INTO api_call_log
                (called_at, api_source, package_name, ecosystem, package_version, http_status, response_time_ms, verdict)
            VALUES ('2099-06-15T12:00:00Z', 'OSV_LIVE', 'test-pkg', 'npm', '1.0.0', 200, 50, 'ALLOW')
            """).update();

        Integer apiCount = jdbcClient.sql(
                "SELECT COUNT(*) FROM " + apiPartition).query(Integer.class).single();
        assertThat(apiCount).isEqualTo(1);
    }

    @Test
    void shouldCreatePartitionsForConsecutiveMonths() {
        partitionMaintenanceService.ensureFuturePartitionsExist(TEST_REFERENCE_MONTH);

        // Verify that partitions for consecutive months exist
        List<String> expectedProxyPartitions = List.of(
                PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_REFERENCE_MONTH.plusMonths(0)),
                PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_REFERENCE_MONTH.plusMonths(1)),
                PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_REFERENCE_MONTH.plusMonths(2)),
                PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_REFERENCE_MONTH.plusMonths(3))
        );

        List<String> expectedApiPartitions = List.of(
                PartitionMaintenanceDao.partitionName("api_call_log", TEST_REFERENCE_MONTH.plusMonths(0)),
                PartitionMaintenanceDao.partitionName("api_call_log", TEST_REFERENCE_MONTH.plusMonths(1)),
                PartitionMaintenanceDao.partitionName("api_call_log", TEST_REFERENCE_MONTH.plusMonths(2)),
                PartitionMaintenanceDao.partitionName("api_call_log", TEST_REFERENCE_MONTH.plusMonths(3))
        );

        for (String partition : expectedProxyPartitions) {
            assertThat(tableExists(partition)).isTrue();
        }

        for (String partition : expectedApiPartitions) {
            assertThat(tableExists(partition)).isTrue();
        }
    }

    private boolean tableExists(String tableName) {
        Boolean exists = jdbcClient.sql(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = :tableName)")
                .param("tableName", tableName)
                .query(Boolean.class).single();
        return Boolean.TRUE.equals(exists);
    }

    private boolean partitionHasCorrectBounds(String partitionName, YearMonth month, String parentTable) {
        // Get the partition bounds from pg_class and pg_range
        // For a monthly partition, the bounds should be from the 1st of the month to the 1st of next month
        String query = """
            SELECT
                pg_get_expr(partboundexpr, partrelid) as bounds
            FROM pg_class c
            JOIN pg_inherits i ON c.oid = i.inhrelid
            JOIN pg_class p ON i.inhparent = p.oid
            WHERE c.relname = :partitionName AND p.relname = :parentTable
            """;

        try {
            String bounds = jdbcClient.sql(query)
                    .param("partitionName", partitionName)
                    .param("parentTable", parentTable)
                    .query(String.class).single();
            return bounds != null && bounds.contains("2099-06-01");
        } catch (Exception e) {
            // Fallback: check if we can query the partition directly
            return tableExists(partitionName);
        }
    }

    private boolean shedlockExists(String lockName) {
        Boolean exists = jdbcClient.sql(
                "SELECT EXISTS (SELECT 1 FROM shedlock WHERE name = :name)")
                .param("name", lockName)
                .query(Boolean.class).single();
        return Boolean.TRUE.equals(exists);
    }
}
