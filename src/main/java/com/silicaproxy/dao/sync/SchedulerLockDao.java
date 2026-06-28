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
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
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

    private final JdbcClient jdbcClient;

    public SchedulerLockDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<Instant> findLockUntil(String lockName) {
        return jdbcClient.sql("SELECT lock_until FROM shedlock WHERE name = :name")
                .param("name", lockName)
                .query(Timestamp.class)
                .optional()
                .map(Timestamp::toInstant);
    }
}
