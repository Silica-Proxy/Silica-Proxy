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


package com.silicaproxy.dao.audit;

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.YearMonth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class PartitionMaintenanceDaoTest extends BaseIntegrationTest {

    // Far enough in the future that it can never collide with the real partitions Flyway
    // creates (proxy_audit_logs_y2026m06/07/08) or with any other test's expectations.
    private static final YearMonth TEST_MONTH_1 = YearMonth.of(2099, 1);
    private static final YearMonth TEST_MONTH_2 = YearMonth.of(2099, 2);

    private final PartitionMaintenanceDao partitionMaintenanceDao;
    private final JdbcClient jdbcClient;

    @Autowired
    PartitionMaintenanceDaoTest(PartitionMaintenanceDao partitionMaintenanceDao, JdbcClient jdbcClient) {
        this.partitionMaintenanceDao = partitionMaintenanceDao;
        this.jdbcClient = jdbcClient;
    }

    @AfterEach
    void dropTestPartitions() {
        jdbcClient.sql("DROP TABLE IF EXISTS " + PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_MONTH_1)).update();
        jdbcClient.sql("DROP TABLE IF EXISTS " + PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_MONTH_2)).update();
    }

    @Test
    void shouldCreatePartitionForFutureMonth() {
        partitionMaintenanceDao.ensureMonthlyPartitionExists("proxy_audit_logs", TEST_MONTH_1);

        assertThat(tableExists(PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_MONTH_1))).isTrue();
    }

    @Test
    void shouldBeIdempotentWhenCalledTwiceForTheSameMonth() {
        partitionMaintenanceDao.ensureMonthlyPartitionExists("proxy_audit_logs", TEST_MONTH_2);

        assertThatCode(() -> partitionMaintenanceDao.ensureMonthlyPartitionExists("proxy_audit_logs", TEST_MONTH_2))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldAcceptRowsWithinTheCreatedPartitionsRange() {
        partitionMaintenanceDao.ensureMonthlyPartitionExists("proxy_audit_logs", TEST_MONTH_1);

        // If the partition's FOR VALUES bounds were wrong, this insert would fail with
        // "no partition of relation \"proxy_audit_logs\" found for row".
        jdbcClient.sql("""
            INSERT INTO proxy_audit_logs
                (timestamp, package_name, package_version, ecosystem, decision_source, verdict, execution_time_ms)
            VALUES ('2099-01-15T00:00:00Z', 'partition-test-pkg', '1.0.0', 'npm', 'COMPANY_POLICY', 'ALLOW', 1)
            """).update();

        Integer count = jdbcClient.sql(
                "SELECT COUNT(*) FROM " + PartitionMaintenanceDao.partitionName("proxy_audit_logs", TEST_MONTH_1)
                        + " WHERE package_name = 'partition-test-pkg'")
                .query(Integer.class).single();
        assertThat(count).isEqualTo(1);
    }

    private boolean tableExists(String tableName) {
        Boolean exists = jdbcClient.sql(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = :tableName)")
                .param("tableName", tableName)
                .query(Boolean.class).single();
        return Boolean.TRUE.equals(exists);
    }
}
