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


package com.silicaproxy.service.decision;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

// Calls DAO methods directly (same pattern as ApiCacheCleanupServiceTest) to avoid
// ShedLock conflicts with the scheduled task that runs concurrently in the test context.
class ExternalValidationCleanupServiceTest extends BaseIntegrationTest {

    private final ExternalValidationCacheDao cacheDao;
    private final JdbcClient jdbcClient;

    @Autowired
    ExternalValidationCleanupServiceTest(ExternalValidationCacheDao cacheDao, JdbcClient jdbcClient) {
        this.cacheDao = cacheDao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE shedlock RESTART IDENTITY CASCADE").update();
    }

    // Test 34 — expiredPending_isMarkedTimeout
    @Test
    void expiredPending_isMarkedTimeout() {
        cacheDao.upsertPendingAsync(
                UUID.randomUUID(), "svc", "lodash", "npm", "4.17.21",
                Instant.now().minus(1, ChronoUnit.MINUTES));

        int timedOut = cacheDao.expireTimedOutPending();
        assertThat(timedOut).isEqualTo(1);

        var entry = cacheDao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("TIMEOUT");
    }

    // Test 35 — expiredAllowed_isDeleted
    @Test
    void expiredAllowed_isDeleted() {
        cacheDao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        cacheDao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().minus(1, ChronoUnit.MINUTES));

        int deleted = cacheDao.deleteExpiredEntries();
        assertThat(deleted).isEqualTo(1);
        assertThat(cacheDao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isEmpty();
    }

    // Test 36 — expiredTimeout_isDeleted
    @Test
    void expiredTimeout_isDeleted() {
        cacheDao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().minus(2, ChronoUnit.MINUTES));
        // expireTimedOutPending sets expires_at to now() — so it's immediately "expired"
        cacheDao.expireTimedOutPending();

        int deleted = cacheDao.deleteExpiredEntries();
        assertThat(deleted).isEqualTo(1);
        assertThat(cacheDao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isEmpty();
    }

    // Test 34b — validPending_isNotExpired
    @Test
    void validPending_isNotTouchedByCleanup() {
        cacheDao.upsertPendingAsync(
                UUID.randomUUID(), "svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        int timedOut = cacheDao.expireTimedOutPending();
        int deleted = cacheDao.deleteExpiredEntries();

        assertThat(timedOut).isEqualTo(0);
        assertThat(deleted).isEqualTo(0);
        var entry = cacheDao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("PENDING");
    }

    // Test 35b — validAllowed_isNotDeleted
    @Test
    void validAllowed_isNotDeletedByCleanup() {
        cacheDao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        cacheDao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        int deleted = cacheDao.deleteExpiredEntries();

        assertThat(deleted).isEqualTo(0);
        assertThat(cacheDao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isPresent();
    }

    // Test 36b — mixed: expired and valid entries in same run
    @Test
    void cleanupOnlyDeletesExpiredEntries() {
        // Expired ALLOWED
        cacheDao.upsertPendingSync("svc", "expired-pkg", "npm", "1.0.0",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        cacheDao.updateToAllowed("svc", "expired-pkg", "npm", "1.0.0", null,
                Instant.now().minus(1, ChronoUnit.MINUTES));

        // Valid ALLOWED
        cacheDao.upsertPendingSync("svc", "valid-pkg", "npm", "2.0.0",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        cacheDao.updateToAllowed("svc", "valid-pkg", "npm", "2.0.0", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        int deleted = cacheDao.deleteExpiredEntries();

        assertThat(deleted).isEqualTo(1);
        assertThat(cacheDao.findByServiceAndPackage("svc", "expired-pkg", "npm", "1.0.0")).isEmpty();
        assertThat(cacheDao.findByServiceAndPackage("svc", "valid-pkg", "npm", "2.0.0")).isPresent();
    }

    // Verify verdicts table is not touched by cleanup
    @Test
    void verdictsTable_isNotTouchedByCleanup() {
        jdbcClient.sql("""
            INSERT INTO external_validation_verdicts (service_name, package_name, ecosystem, package_version, reason)
            VALUES ('svc', 'lodash', 'npm', '4.17.21', 'Old block')
            """).update();

        // Cleanup only touches cache table
        cacheDao.expireTimedOutPending();
        cacheDao.deleteExpiredEntries();

        long count = jdbcClient.sql("SELECT COUNT(*) FROM external_validation_verdicts")
                .query(Long.class).single();
        assertThat(count).isEqualTo(1);
    }
}
