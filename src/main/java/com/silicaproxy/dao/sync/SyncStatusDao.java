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


package com.silicaproxy.dao.sync;

import com.silicaproxy.model.dto.SyncStatusRow;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * SQL access to the table {@code sync_status} (status of 7 synchronization jobs : 6 vulnerability 
 * sources + GitOps). Called by {@code VulnerabilitySyncStatusService} at each 
 * start/advancement/end of scheduled job, and at each query of 
 * {@code GET /api/vulnerabilities/sync/status}.
 */
@Repository
@NullMarked
public class SyncStatusDao {

    private final JdbcClient jdbcClient;

    public SyncStatusDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    // SQL expression applying the correct expiration threshold according to the job 
    // (gitops-sync is bounded by a lockAtMostFor of 10 minutes, vulnerability jobs by 1 hour).
    private String staleThresholdCaseExpression(String gitopsJobId, long gitopsThresholdMinutes, long vulnerabilityThresholdMinutes) {
        return "(CASE WHEN job_id = '%s' THEN INTERVAL '%d minutes' ELSE INTERVAL '%d minutes' END)"
                .formatted(gitopsJobId, gitopsThresholdMinutes, vulnerabilityThresholdMinutes);
    }

    @Transactional
    public int recoverStaleRunningJobs(String gitopsJobId, long gitopsThresholdMinutes, long vulnerabilityThresholdMinutes) {
        String caseExpr = staleThresholdCaseExpression(gitopsJobId, gitopsThresholdMinutes, vulnerabilityThresholdMinutes);
        return jdbcClient.sql("UPDATE sync_status"
                + " SET status = 'FAILED',"
                + " error_message = 'Synchronization interrupted by a stop or a restart of instance',"
                + " last_end_time = CURRENT_TIMESTAMP,"
                + " updated_at = CURRENT_TIMESTAMP"
                + " WHERE status = 'RUNNING'"
                + " AND last_start_time < CURRENT_TIMESTAMP - " + caseExpr)
                .update();
    }

    public boolean isJobRunningWithinThreshold(String jobId, long thresholdMinutes) {
        Long count = jdbcClient.sql("SELECT count(*) FROM sync_status"
                + " WHERE job_id = :jobId AND status = 'RUNNING'"
                + " AND last_start_time > CURRENT_TIMESTAMP - INTERVAL '" + thresholdMinutes + " minutes'")
                .param("jobId", jobId)
                .query(Long.class)
                .single();
        return count != null && count > 0;
    }

    public long countRunningWithinThreshold(String gitopsJobId, long gitopsThresholdMinutes, long vulnerabilityThresholdMinutes) {
        String caseExpr = staleThresholdCaseExpression(gitopsJobId, gitopsThresholdMinutes, vulnerabilityThresholdMinutes);
        Long count = jdbcClient.sql("SELECT count(*) FROM sync_status"
                + " WHERE status = 'RUNNING'"
                + " AND last_start_time > CURRENT_TIMESTAMP - " + caseExpr)
                .query(Long.class)
                .single();
        return count;
    }

    public List<SyncStatusRow> findAllJobs() {
        List<Map<String, Object>> rows = jdbcClient.sql("""
                SELECT job_id, status, last_start_time, last_end_time, duration_ms, error_message, items_processed, next_run_time, items_total
                FROM sync_status
                ORDER BY job_id
                """)
                .query()
                .listOfRows();

        List<SyncStatusRow> result = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            Timestamp startTs = (Timestamp) row.get("last_start_time");
            Timestamp endTs = (Timestamp) row.get("last_end_time");
            Number duration = (Number) row.get("duration_ms");
            Number items = (Number) row.get("items_processed");
            Timestamp nextTs = (Timestamp) row.get("next_run_time");
            Number itemsTotal = (Number) row.get("items_total");

            result.add(new SyncStatusRow(
                    (String) row.get("job_id"),
                    (String) row.get("status"),
                    startTs != null ? startTs.toInstant() : null,
                    endTs != null ? endTs.toInstant() : null,
                    duration != null ? duration.longValue() : null,
                    (String) row.get("error_message"),
                    items != null ? items.longValue() : 0L,
                    nextTs != null ? nextTs.toInstant() : null,
                    itemsTotal != null ? itemsTotal.longValue() : null
            ));
        }
        return result;
    }

    @Transactional
    public void startTask(String taskId) {
        jdbcClient.sql("""
                UPDATE sync_status
                SET status = 'RUNNING',
                    last_start_time = CURRENT_TIMESTAMP,
                    last_end_time = NULL,
                    duration_ms = NULL,
                    error_message = NULL,
                    items_processed = 0,
                    items_total = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_id = :jobId
                """)
                .param("jobId", taskId)
                .update();
    }

    @Transactional
    public void incrementItemsProcessed(String taskId, int count) {
        jdbcClient.sql("""
                UPDATE sync_status
                SET items_processed = items_processed + :count,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_id = :jobId AND status = 'RUNNING'
                """)
                .param("jobId", taskId)
                .param("count", count)
                .update();
    }

    @Transactional
    public void setItemsTotal(String taskId, long itemsTotal) {
        jdbcClient.sql("""
                UPDATE sync_status
                SET items_total = :itemsTotal,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_id = :jobId AND status = 'RUNNING'
                """)
                .param("jobId", taskId)
                .param("itemsTotal", itemsTotal)
                .update();
    }

    @Transactional
    public void updateProgress(String taskId, long itemsProcessed, long itemsTotal) {
        jdbcClient.sql("""
                UPDATE sync_status
                SET items_processed = :itemsProcessed,
                    items_total = :itemsTotal,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_id = :jobId AND status = 'RUNNING'
                """)
                .param("jobId", taskId)
                .param("itemsProcessed", itemsProcessed)
                .param("itemsTotal", itemsTotal)
                .update();
    }

    public Optional<Instant> findLastStartTime(String taskId) {
        return jdbcClient.sql("SELECT last_start_time FROM sync_status WHERE job_id = :jobId")
                .param("jobId", taskId)
                .query(Timestamp.class)
                .optional()
                .map(Timestamp::toInstant);
    }

    public Optional<Instant> findLastEndTime(String taskId) {
        return jdbcClient.sql("SELECT last_end_time FROM sync_status WHERE job_id = :jobId")
                .param("jobId", taskId)
                .query(Timestamp.class)
                .optional()
                .flatMap(ts -> ts != null ? java.util.Optional.of(ts.toInstant()) : java.util.Optional.empty());
    }

    @Transactional
    public void completeTask(String taskId, Instant endTime, @Nullable Long durationMs, @Nullable Instant nextRunTime) {
        jdbcClient.sql("""
                UPDATE sync_status
                SET status = 'SUCCESS',
                    last_end_time = :endTime,
                    duration_ms = :durationMs,
                    next_run_time = :nextRunTime,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_id = :jobId
                """)
                .param("jobId", taskId)
                .param("endTime", Timestamp.from(endTime))
                .param("durationMs", durationMs)
                .param("nextRunTime", nextRunTime != null ? Timestamp.from(nextRunTime) : null)
                .update();
    }

    @Transactional
    public void failTask(String taskId, Instant endTime, @Nullable Long durationMs, @Nullable String errorMessage, @Nullable Instant nextRunTime) {
        jdbcClient.sql("""
                UPDATE sync_status
                SET status = 'FAILED',
                    last_end_time = :endTime,
                    duration_ms = :durationMs,
                    error_message = :errorMessage,
                    next_run_time = :nextRunTime,
                    updated_at = CURRENT_TIMESTAMP
                WHERE job_id = :jobId
                """)
                .param("jobId", taskId)
                .param("endTime", Timestamp.from(endTime))
                .param("durationMs", durationMs)
                .param("errorMessage", errorMessage)
                .param("nextRunTime", nextRunTime != null ? Timestamp.from(nextRunTime) : null)
                .update();
    }
}
