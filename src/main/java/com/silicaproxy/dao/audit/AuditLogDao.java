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

import com.silicaproxy.model.entity.AuditLog;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import io.micrometer.core.annotation.Timed;

import java.sql.Timestamp;

/**
 * Writes a line in the partitioned table, with
 * {@code synchronous_commit} disabled for this transaction  to maximize 
 * write throughput without blocking the security check.
 */
@Repository
@NullMarked
public class AuditLogDao {

    private final JdbcClient jdbcClient;

    public AuditLogDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Transactional
    @Timed(value = "silicaproxy.dao.auditlog.save", description = "Duration of writing an SQL audit line", percentiles = {0.5, 0.9, 0.95, 0.99})
    public void save(AuditLog auditLog) {
        // IO throughput optimization under Loom : disabling synchronous_commit for this audit transaction
        jdbcClient.sql("SET LOCAL synchronous_commit = off").update();

        String sql = """
            INSERT INTO proxy_audit_logs (timestamp, package_name, package_version, ecosystem, decision_source, verdict, reason, execution_time_ms)
            VALUES (:timestamp, :packageName, :packageVersion, :ecosystem, :decisionSource, :verdict, :reason, :executionTimeMs)
            """;

        jdbcClient.sql(sql)
                .param("timestamp", Timestamp.from(auditLog.timestamp()))
                .param("packageName", auditLog.packageName())
                .param("packageVersion", auditLog.packageVersion())
                .param("ecosystem", auditLog.ecosystem())
                .param("decisionSource", auditLog.decisionSource())
                .param("verdict", auditLog.verdict())
                .param("reason", auditLog.reason())
                .param("executionTimeMs", auditLog.executionTimeMs())
                .update();
    }
}
