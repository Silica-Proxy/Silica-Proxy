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

import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

/**
 * Read access to the table {@code shedlock} (ShedLock distributed locking, SchedulerConfig).
 * Called by {@code VulnerabilitySyncStatusService} to expose to force-sync endpoints the
 * release date of a lock still held (ex : {@code lockAtLeastFor} not yet elapsed,
 * even if the corresponding job is already completed on {@code sync_status} side).
 */
@Repository
@NullMarked
public class SchedulerLockDao {

    // The clock ShedLock writes lock_until with (usingDbTime, PostgreSQL) : the UTC wall-clock time,
    // a TIMESTAMP without time zone stored into a TIMESTAMPTZ column, so read back in the time zone
    // of the session. Compared with this expression, never with CURRENT_TIMESTAMP : under a JVM
    // outside UTC (Europe/Paris, +2h), a lock of 50 min would look expired since 1h10.
    public static final String SHEDLOCK_NOW = "timezone('utc', CURRENT_TIMESTAMP)";

    private final JdbcClient jdbcClient;

    public SchedulerLockDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    // The time left before lockName is released, negative once it is.
    @Timed(value = "silicaproxy.dao.schedulerlock.findremaininglock",
            description = "Duration of reading the remaining duration of a ShedLock lock",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<Duration> findRemainingLock(String lockName) {
        return jdbcClient.sql("SELECT EXTRACT(EPOCH FROM (lock_until - " + SHEDLOCK_NOW + ")) FROM shedlock WHERE name = :name")
                .param("name", lockName)
                .query(Double.class)
                .optional()
                .map(seconds -> Duration.ofMillis(Math.round(seconds * 1000)));
    }
}
