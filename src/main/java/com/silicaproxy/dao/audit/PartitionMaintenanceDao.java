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

import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.YearMonth;

/**
 * Creates monthly RANGE partitions for the partitioned audit tables ({@code proxy_audit_logs},
 * {@code api_call_log}). Table/column identifiers here are never derived from external input --
 * only from a fixed, code-controlled table name and the system clock -- so they are built
 * directly into the DDL string rather than bound as JDBC parameters (identifiers, unlike values,
 * cannot be parameterized).
 */
@Repository
@NullMarked
public class PartitionMaintenanceDao {

    private final JdbcClient jdbcClient;

    public PartitionMaintenanceDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /**
     * Creates the partition {@code {parentTable}_y{year}m{month}} covering {@code month} if it
     * doesn't already exist. Idempotent: PostgreSQL's {@code CREATE TABLE IF NOT EXISTS} applies
     * to the {@code PARTITION OF} form too, so calling this repeatedly for the same month is safe.
     */
    public void ensureMonthlyPartitionExists(String parentTable, YearMonth month) {
        String partitionName = partitionName(parentTable, month);
        LocalDate start = month.atDay(1);
        LocalDate end = month.plusMonths(1).atDay(1);

        String sql = "CREATE TABLE IF NOT EXISTS " + partitionName
                + " PARTITION OF " + parentTable
                + " FOR VALUES FROM ('" + start + " 00:00:00+00') TO ('" + end + " 00:00:00+00')";
        jdbcClient.sql(sql).update();
    }

    public static String partitionName(String parentTable, YearMonth month) {
        return parentTable + "_y" + month.getYear() + "m" + String.format("%02d", month.getMonthValue());
    }
}
