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

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class SyncRunHistoryDaoTest extends BaseIntegrationTest {

    private static final String JOB_ID = "test-run-history";

    private final SyncRunHistoryDao syncRunHistoryDao;
    private final JdbcClient jdbcClient;

    @Autowired
    SyncRunHistoryDaoTest(SyncRunHistoryDao syncRunHistoryDao, JdbcClient jdbcClient) {
        this.syncRunHistoryDao = syncRunHistoryDao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("DELETE FROM sync_run_history WHERE job_id = :jobId").param("jobId", JOB_ID).update();
    }

    private Instant insertRun(String status, String startedAgo) {
        return jdbcClient.sql("INSERT INTO sync_run_history (job_id, sync_type, started_at, ended_at, status)"
                        + " VALUES (:jobId, 'OSV_INCREMENTAL', CURRENT_TIMESTAMP - CAST(:ago AS INTERVAL),"
                        + " CASE WHEN :status = 'RUNNING' THEN NULL"
                        + " ELSE CURRENT_TIMESTAMP - CAST(:ago AS INTERVAL) + INTERVAL '1 minute' END, :status)"
                        + " RETURNING started_at")
                .param("jobId", JOB_ID)
                .param("ago", startedAgo)
                .param("status", status)
                .query(Timestamp.class).single().toInstant();
    }

    @Test
    void shouldFindTheLastSuccessfulRunIgnoringMoreRecentFailedOrRunningOnes() {
        insertRun("SUCCESS", "3 hours");
        Instant lastSuccessStart = insertRun("SUCCESS", "2 hours");
        insertRun("FAILED", "1 hour");
        insertRun("RUNNING", "1 minute");

        assertThat(syncRunHistoryDao.findLastSuccessfulStart(JOB_ID)).contains(lastSuccessStart);
        assertThat(syncRunHistoryDao.findLastSuccessfulEnd(JOB_ID)).contains(lastSuccessStart.plusSeconds(60));
    }

    @Test
    void shouldFindNothingWhenNoRunSucceeded() {
        insertRun("FAILED", "1 hour");
        insertRun("RUNNING", "1 minute");

        assertThat(syncRunHistoryDao.findLastSuccessfulStart(JOB_ID)).isEmpty();
        assertThat(syncRunHistoryDao.findLastSuccessfulEnd(JOB_ID)).isEmpty();
    }

    @Test
    void shouldReadTheRunsRecordedThroughTheDao() {
        long runId = syncRunHistoryDao.startRun(JOB_ID, "OSV_INCREMENTAL", "npm", null, null);
        syncRunHistoryDao.completeRun(runId, 0L, 0, 0, 0, 0, null);
        long failedRunId = syncRunHistoryDao.startRun(JOB_ID, "OSV_INCREMENTAL", "npm", null, null);
        syncRunHistoryDao.failRun(failedRunId, "java.lang.OutOfMemoryError: test", 0);

        Instant started = jdbcClient.sql("SELECT started_at FROM sync_run_history WHERE id = :id")
                .param("id", runId).query(Timestamp.class).single().toInstant();
        assertThat(syncRunHistoryDao.findLastSuccessfulStart(JOB_ID)).contains(started);
    }
}
