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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class UpstreamHeadCacheDaoTest extends BaseIntegrationTest {

    private static final String URL = "https://plugins.gradle.org/m2/com/github/spotbugs/snom/spotbugs-gradle-plugin/6.5.13/spotbugs-gradle-plugin-6.5.13.pom";

    private final UpstreamHeadCacheDao dao;
    private final JdbcClient jdbcClient;

    @Autowired
    UpstreamHeadCacheDaoTest(UpstreamHeadCacheDao dao, JdbcClient jdbcClient) {
        this.dao = dao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE upstream_head_cache").update();
    }

    @Test
    void findStatus_noEntry_returnsEmpty() {
        assertThat(dao.findStatus(URL)).isEmpty();
    }

    @Test
    void upsert_thenFindStatus_returnsStoredStatus() {
        dao.upsert(URL, "EXISTS", Instant.now().plus(10, ChronoUnit.MINUTES));

        assertThat(dao.findStatus(URL)).contains("EXISTS");
    }

    @Test
    void upsert_onConflict_replacesStatus() {
        Instant later = Instant.now().plus(10, ChronoUnit.MINUTES);
        dao.upsert(URL, "NOT_FOUND", later);
        dao.upsert(URL, "EXISTS", later);

        assertThat(dao.findStatus(URL)).contains("EXISTS");
        long count = jdbcClient.sql("SELECT COUNT(*) FROM upstream_head_cache")
                .query(Long.class).single();
        assertThat(count).isEqualTo(1);
    }

    @Test
    void findStatus_expiredRow_isIgnored() {
        dao.upsert(URL, "NOT_FOUND", Instant.now().minus(1, ChronoUnit.MINUTES));

        assertThat(dao.findStatus(URL)).isEmpty();
    }

    @Test
    void deleteExpired_removesOnlyExpiredRows() {
        dao.upsert(URL, "NOT_FOUND", Instant.now().minus(1, ChronoUnit.MINUTES));
        dao.upsert(URL + "?other", "EXISTS", Instant.now().plus(10, ChronoUnit.MINUTES));

        int deleted = dao.deleteExpired();

        assertThat(deleted).isEqualTo(1);
        assertThat(dao.findStatus(URL + "?other")).contains("EXISTS");
    }
}
