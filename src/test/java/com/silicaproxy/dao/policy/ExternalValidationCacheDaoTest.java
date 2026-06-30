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


package com.silicaproxy.dao.policy;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ExternalValidationCacheDaoTest extends BaseIntegrationTest {

    private final ExternalValidationCacheDao dao;
    private final JdbcClient jdbcClient;

    @Autowired
    ExternalValidationCacheDaoTest(ExternalValidationCacheDao dao, JdbcClient jdbcClient) {
        this.dao = dao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
    }

    // Test 1 — findByServiceAndPackage_noEntry_returnsEmpty
    @Test
    void findByServiceAndPackage_noEntry_returnsEmpty() {
        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isEmpty();
    }

    // Test 2 — upsertPendingSync inserts row with null token
    @Test
    void upsertPendingSync_insertsNewRowWithNullToken() {
        Instant expiry = Instant.now().plus(30, ChronoUnit.MINUTES);
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21", expiry);

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        ExternalValidationCacheEntry entry = result.get();
        assertThat(entry.status()).isEqualTo("PENDING");
        assertThat(entry.mode()).isEqualTo("SYNC");
        assertThat(entry.callbackToken()).isNull();
        assertThat(entry.expiresAt()).isAfter(Instant.now());
    }

    // Test 3a — upsertPendingAsync inserts row with token
    @Test
    void upsertPendingAsync_insertsNewRowWithToken() {
        UUID token = UUID.randomUUID();
        Instant expiry = Instant.now().plus(30, ChronoUnit.MINUTES);
        dao.upsertPendingAsync(token, "svc", "lodash", "npm", "4.17.21", expiry);

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        ExternalValidationCacheEntry entry = result.get();
        assertThat(entry.status()).isEqualTo("PENDING");
        assertThat(entry.mode()).isEqualTo("ASYNC");
        assertThat(entry.callbackToken()).isEqualTo(token);
    }

    // Test 3b — upsert on conflict replaces token and resets to PENDING
    @Test
    void upsertPendingAsync_conflict_replacesWithNewToken() {
        UUID token1 = UUID.randomUUID();
        UUID token2 = UUID.randomUUID();
        Instant expiry = Instant.now().plus(30, ChronoUnit.MINUTES);

        dao.upsertPendingAsync(token1, "svc", "lodash", "npm", "4.17.21", expiry);
        dao.upsertPendingAsync(token2, "svc", "lodash", "npm", "4.17.21", expiry);

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().callbackToken()).isEqualTo(token2);
        assertThat(result.get().status()).isEqualTo("PENDING");

        long count = jdbcClient.sql("SELECT COUNT(*) FROM external_validation_cache")
                .query(Long.class).single();
        assertThat(count).isEqualTo(1);
    }

    // Test 4 — updateToAllowed updates status and expiry
    @Test
    void updateToAllowed_updatesStatusReasonAndExpiry() {
        Instant pendingExpiry = Instant.now().plus(30, ChronoUnit.MINUTES);
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21", pendingExpiry);

        Instant cacheExpiry = Instant.now().plus(60, ChronoUnit.MINUTES);
        dao.updateToAllowed("svc", "lodash", "npm", "4.17.21", "Clean package", cacheExpiry);

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo("ALLOWED");
        assertThat(result.get().reason()).isEqualTo("Clean package");
        assertThat(result.get().expiresAt()).isAfter(pendingExpiry);
    }

    // Test 54 — updateToAllowed after TIMEOUT also works (re-scan scenario)
    @Test
    void updateToAllowed_afterTimeout_updatesStatus() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().minus(1, ChronoUnit.MINUTES));
        dao.updateToTimeout("svc", "lodash", "npm", "4.17.21");

        dao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo("ALLOWED");
    }

    // Test 5 — updateToAllowedByToken with unknown token returns false
    @Test
    void updateToAllowedByToken_unknownToken_returnsFalse() {
        boolean updated = dao.updateToAllowedByToken(
                UUID.randomUUID(), "reason", Instant.now().plus(60, ChronoUnit.MINUTES));
        assertThat(updated).isFalse();
    }

    // Test 6 — updateToAllowedByToken on already-resolved entry returns false
    @Test
    void updateToAllowedByToken_entryNotPending_returnsFalse() {
        UUID token = UUID.randomUUID();
        dao.upsertPendingAsync(token, "svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));
        dao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        boolean updated = dao.updateToAllowedByToken(
                token, "late callback", Instant.now().plus(60, ChronoUnit.MINUTES));
        assertThat(updated).isFalse();
    }

    // Test 7 — findByCallbackToken found
    @Test
    void findByCallbackToken_found() {
        UUID token = UUID.randomUUID();
        dao.upsertPendingAsync(token, "svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        Optional<ExternalValidationCacheEntry> result = dao.findByCallbackToken(token);
        assertThat(result).isPresent();
        assertThat(result.get().callbackToken()).isEqualTo(token);
        assertThat(result.get().packageName()).isEqualTo("lodash");
    }

    // Test 53 — findByCallbackToken not found
    @Test
    void findByCallbackToken_notFound_returnsEmpty() {
        Optional<ExternalValidationCacheEntry> result =
                dao.findByCallbackToken(UUID.randomUUID());
        assertThat(result).isEmpty();
    }

    // Test 8 — expireTimedOutPending sets TIMEOUT on expired PENDING
    @Test
    void expireTimedOutPending_pendingExpired_setsTimeout() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().minus(1, ChronoUnit.MINUTES));

        int updated = dao.expireTimedOutPending();

        assertThat(updated).isEqualTo(1);
        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo("TIMEOUT");
    }

    // Test 9 — expireTimedOutPending leaves valid PENDING untouched
    @Test
    void expireTimedOutPending_pendingNotExpired_doesNothing() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        int updated = dao.expireTimedOutPending();

        assertThat(updated).isEqualTo(0);
        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result.get().status()).isEqualTo("PENDING");
    }

    // Test 10 — deleteExpiredEntries removes expired ALLOWED
    @Test
    void deleteExpiredEntries_deletesExpiredAllowed() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        dao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().minus(1, ChronoUnit.MINUTES));

        int deleted = dao.deleteExpiredEntries();

        assertThat(deleted).isEqualTo(1);
        assertThat(dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isEmpty();
    }

    // Test 55 — findByServiceAndPackage returns expired entries (service layer decides)
    @Test
    void findByServiceAndPackage_expiredEntry_returnsIt() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().minus(1, ChronoUnit.MINUTES));
        dao.updateToTimeout("svc", "lodash", "npm", "4.17.21");

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo("TIMEOUT");
    }

    // Test 56 — deleteExpiredEntries does NOT delete PENDING (even expired)
    @Test
    void deleteExpiredEntries_doesNotDeletePending() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().minus(1, ChronoUnit.MINUTES));

        int deleted = dao.deleteExpiredEntries();

        assertThat(deleted).isEqualTo(0);
        assertThat(dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isPresent();
    }

    // Test 57 — deleteExpiredEntries does NOT delete valid ALLOWED
    @Test
    void deleteExpiredEntries_doesNotDeleteValidAllowed() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        dao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        int deleted = dao.deleteExpiredEntries();

        assertThat(deleted).isEqualTo(0);
        assertThat(dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isPresent();
    }

    // Test 67 — deleteExpiredEntries leaves multiple valid entries untouched
    @Test
    void deleteExpiredEntries_doesNotDeleteNonExpiredResults() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        dao.updateToAllowed("svc", "lodash", "npm", "4.17.21", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));
        dao.upsertPendingSync("svc", "react", "npm", "18.0.0",
                Instant.now().plus(1, ChronoUnit.MINUTES));
        dao.updateToAllowed("svc", "react", "npm", "18.0.0", null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        int deleted = dao.deleteExpiredEntries();

        assertThat(deleted).isEqualTo(0);
        long count = jdbcClient.sql("SELECT COUNT(*) FROM external_validation_cache")
                .query(Long.class).single();
        assertThat(count).isEqualTo(2);
    }

    // Test 68 — valid PENDING survives both cleanup operations
    @Test
    void cleanup_doesNotTouchNonExpiredPending() {
        dao.upsertPendingSync("svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        dao.expireTimedOutPending();
        dao.deleteExpiredEntries();

        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo("PENDING");
    }

    // deleteByToken — used when async callback returns BLOCKED
    @Test
    void deleteByToken_pendingEntry_returnsTrue() {
        UUID token = UUID.randomUUID();
        dao.upsertPendingAsync(token, "svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        boolean deleted = dao.deleteByToken(token);

        assertThat(deleted).isTrue();
        assertThat(dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21")).isEmpty();
    }

    @Test
    void deleteByToken_unknownToken_returnsFalse() {
        boolean deleted = dao.deleteByToken(UUID.randomUUID());
        assertThat(deleted).isFalse();
    }

    // updateToAllowedByToken — used when async callback returns ALLOWED
    @Test
    void updateToAllowedByToken_pendingEntry_updatesAndReturnsTrue() {
        UUID token = UUID.randomUUID();
        dao.upsertPendingAsync(token, "svc", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        Instant cacheExpiry = Instant.now().plus(60, ChronoUnit.MINUTES);
        boolean updated = dao.updateToAllowedByToken(token, "No threats", cacheExpiry);

        assertThat(updated).isTrue();
        Optional<ExternalValidationCacheEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().status()).isEqualTo("ALLOWED");
        assertThat(result.get().reason()).isEqualTo("No threats");
        assertThat(result.get().expiresAt()).isAfter(Instant.now());
    }
}
