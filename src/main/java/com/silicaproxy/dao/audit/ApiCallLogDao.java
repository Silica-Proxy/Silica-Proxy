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

import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Records each call to external security APIs.
 *
 * <p><strong>Performance :</strong> this feature is disabled by default
 * ({@code silicaproxy.api-call-log.enabled: false}). In high-traffic environments, 
 * each unknown package generates an API call and thus a line in this table 
 * — enable it only with a PostgreSQL sized accordingly.
 */
@Repository
@NullMarked
public class ApiCallLogDao {

    private static final Logger LOG = LoggerFactory.getLogger(ApiCallLogDao.class);
    private static final int MAX_BATCH_SIZE = 500;

    private record ApiCallEntry(
            String apiSource,
            String packageName,
            String ecosystem,
            String packageVersion,
            int httpStatus,
            int responseTimeMs,
            String verdict,
            int vulnerabilitiesCount,
            @Nullable String errorMessage) {}

    private final JdbcTemplate jdbcTemplate;
    private final SilicaProxyProperties properties;
    private final LinkedBlockingQueue<ApiCallEntry> buffer;

    public ApiCallLogDao(JdbcTemplate jdbcTemplate, SilicaProxyProperties properties) {
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
        this.buffer = new LinkedBlockingQueue<>(properties.apiCallLog().bufferCapacity());
    }

    public void logCall(
            String apiSource,
            String packageName,
            String ecosystem,
            String packageVersion,
            String verdict,
            ApiCheckResult checkResult) {
        if (!properties.apiCallLog().enabled()) {
            return;
        }
        int cappedMs = (int) Math.min(checkResult.responseTimeMs(), Integer.MAX_VALUE);
        ApiCallEntry entry = new ApiCallEntry(apiSource, packageName, ecosystem, packageVersion,
                checkResult.httpStatus(), cappedMs, verdict,
                checkResult.vulnerabilitiesCount(), checkResult.errorMessage());
        if (!buffer.offer(entry)) {
            LOG.warn("api_call_log buffer full ({} entries) — entry discarded for {}/{}",
                    buffer.size(), ecosystem, packageName);
        }
    }

    @Scheduled(fixedDelayString = "${silicaproxy.api-call-log.flush-interval-seconds:30}000")
    public void flushBuffer() {
        if (!properties.apiCallLog().enabled() || buffer.isEmpty()) {
            return;
        }
        List<ApiCallEntry> batch = new ArrayList<>(MAX_BATCH_SIZE);
        while (!buffer.isEmpty()) {
            batch.clear();
            buffer.drainTo(batch, MAX_BATCH_SIZE);
            if (batch.isEmpty()) {
                break;
            }
            insertBatch(batch);
        }
    }

    private void insertBatch(List<ApiCallEntry> batch) {
        try {
            String sql = "INSERT INTO api_call_log (api_source, package_name, ecosystem, package_version,"
                    + " http_status, response_time_ms, verdict, vulnerabilities_count, error_message)"
                    + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps, int i) throws SQLException {
                    ApiCallEntry e = batch.get(i);
                    ps.setString(1, e.apiSource());
                    ps.setString(2, e.packageName());
                    ps.setString(3, e.ecosystem());
                    ps.setString(4, e.packageVersion());
                    ps.setInt(5, e.httpStatus());
                    ps.setInt(6, e.responseTimeMs());
                    ps.setString(7, e.verdict());
                    ps.setInt(8, e.vulnerabilitiesCount());
                    if (e.errorMessage() != null) {
                        ps.setString(9, e.errorMessage());
                    } else {
                        ps.setNull(9, Types.VARCHAR);
                    }
                }

                @Override
                public int getBatchSize() {
                    return batch.size();
                }
            });
            LOG.debug("api_call_log: flushed {} entries.", batch.size());
        } catch (Exception e) {
            LOG.warn("Failed to flush {} api_call_log entries: {}", batch.size(), e.getMessage());
        }
    }
}
