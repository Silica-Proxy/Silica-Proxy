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

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.Optional;

/**
 * Persists the execution history of each synchronization job in
 * {@code sync_run_history}. Append-only table : one line per execution, never truncated.
 */
@Repository
@NullMarked
public class SyncRunHistoryDao {

    private final JdbcClient jdbcClient;

    public SyncRunHistoryDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public long startRun(
            String jobId,
            String syncType,
            @Nullable String ecosystem,
            @Nullable String sourceUrl,
            @Nullable Instant watermarkFrom) {
        Timestamp watermarkFromTs = watermarkFrom != null ? Timestamp.from(watermarkFrom) : null;
        return jdbcClient.sql("""
                INSERT INTO sync_run_history
                    (job_id, sync_type, ecosystem, source_url, started_at, status, watermark_from)
                VALUES (:jobId, :syncType, :ecosystem, :sourceUrl, CURRENT_TIMESTAMP, 'RUNNING', :watermarkFrom)
                RETURNING id
                """)
                .param("jobId", jobId)
                .param("syncType", syncType)
                .param("ecosystem", ecosystem)
                .param("sourceUrl", sourceUrl)
                .param("watermarkFrom", watermarkFromTs)
                .query(Long.class)
                .single();
    }

    public void completeRun(
            long runId,
            @Nullable Long itemsDiscovered,
            long itemsNew,
            long itemsUpdated,
            long itemsSkipped,
            long itemsFailed,
            @Nullable Instant watermarkTo) {
        Timestamp watermarkToTs = watermarkTo != null ? Timestamp.from(watermarkTo) : null;
        jdbcClient.sql("""
                UPDATE sync_run_history
                SET status = 'SUCCESS',
                    ended_at = CURRENT_TIMESTAMP,
                    duration_ms = ROUND(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) * 1000)::BIGINT,
                    items_discovered = :discovered,
                    items_new = :itemsNew,
                    items_updated = :itemsUpdated,
                    items_skipped = :skipped,
                    items_failed = :failed,
                    watermark_to = :watermarkTo
                WHERE id = :runId
                """)
                .param("runId", runId)
                .param("discovered", itemsDiscovered)
                .param("itemsNew", itemsNew)
                .param("itemsUpdated", itemsUpdated)
                .param("skipped", itemsSkipped)
                .param("failed", itemsFailed)
                .param("watermarkTo", watermarkToTs)
                .update();
    }

    // Closes the RUNNING runs left by a crash, or by a failure failRun could not record : the ones
    // of the jobs that run no longer (SyncStatusDao.NOT_RUNNING), whatever their sync_status row
    // says (failTask may have succeeded where failRun failed).
    public int failOrphanedRuns(@Nullable String ownLockName, String errorMessage) {
        return jdbcClient.sql("UPDATE sync_run_history"
                + " SET status = 'FAILED',"
                + " ended_at = CURRENT_TIMESTAMP,"
                + " duration_ms = ROUND(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) * 1000)::BIGINT,"
                + " error_message = :errorMessage"
                + " WHERE sync_run_history.status = 'RUNNING' AND EXISTS (SELECT 1 FROM sync_status"
                + " WHERE sync_status.job_id = sync_run_history.job_id AND " + SyncStatusDao.NOT_RUNNING + ")")
                .param("ownLockName", ownLockName, Types.VARCHAR)
                .param("errorMessage", errorMessage)
                .update();
    }

    public void failRun(long runId, @Nullable String errorMessage, long itemsFailed) {
        jdbcClient.sql("""
                UPDATE sync_run_history
                SET status = 'FAILED',
                    ended_at = CURRENT_TIMESTAMP,
                    duration_ms = ROUND(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) * 1000)::BIGINT,
                    items_failed = :failed,
                    error_message = :errorMessage
                WHERE id = :runId
                """)
                .param("runId", runId)
                .param("failed", itemsFailed)
                .param("errorMessage", errorMessage)
                .update();
    }

    // The watermark of the hourly sync : the start of its last successful run. A failed run does not
    // move it, and starting from the start (the CSV is read then) leaves no gap while a run lasts.
    public Optional<Instant> findLastSuccessfulStart(String jobId) {
        return jdbcClient.sql("""
                SELECT started_at FROM sync_run_history
                WHERE job_id = :jobId AND status = 'SUCCESS'
                ORDER BY started_at DESC
                LIMIT 1
                """)
                .param("jobId", jobId)
                .query(Timestamp.class)
                .optional()
                .map(Timestamp::toInstant);
    }

    // The end of the last successful run : sorted by started_at, which the index covers (the runs
    // of one job never overlap, so the last one started is also the last one ended).
    public Optional<Instant> findLastSuccessfulEnd(String jobId) {
        return jdbcClient.sql("""
                SELECT ended_at FROM sync_run_history
                WHERE job_id = :jobId AND status = 'SUCCESS'
                ORDER BY started_at DESC
                LIMIT 1
                """)
                .param("jobId", jobId)
                .query(Timestamp.class)
                .optional()
                .map(Timestamp::toInstant);
    }
}
