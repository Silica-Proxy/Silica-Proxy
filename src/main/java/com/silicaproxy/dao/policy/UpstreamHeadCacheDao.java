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

import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * Persistent outcome of the HEAD check run before an external validation service
 * (services.&lt;name&gt;.head-check). Keyed by effective URL, shared by all services and instances.
 */
@Repository
@NullMarked
public class UpstreamHeadCacheDao {

    private final JdbcClient jdbcClient;

    public UpstreamHeadCacheDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** Stored status ({@code EXISTS} or {@code NOT_FOUND}) for {@code url}, ignoring expired rows. */
    @Timed(value = "silicaproxy.dao.upstreamhead.cache.find",
            description = "Duration of upstream HEAD cache lookup",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<String> findStatus(String url) {
        return jdbcClient.sql("""
                SELECT status
                FROM upstream_head_cache
                WHERE url = :url
                  AND expires_at > CURRENT_TIMESTAMP
                """)
                .param("url", url)
                .query(String.class)
                .optional();
    }

    @Timed(value = "silicaproxy.dao.upstreamhead.cache.upsert",
            description = "Duration of upstream HEAD cache upsert",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void upsert(String url, String status, Instant expiresAt) {
        jdbcClient.sql("""
                INSERT INTO upstream_head_cache (url, status, checked_at, expires_at)
                VALUES (:url, :status, CURRENT_TIMESTAMP, :expiresAt)
                ON CONFLICT (url)
                DO UPDATE SET
                    status     = EXCLUDED.status,
                    checked_at = CURRENT_TIMESTAMP,
                    expires_at = EXCLUDED.expires_at
                """)
                .param("url", url)
                .param("status", status)
                .param("expiresAt", Timestamp.from(expiresAt))
                .update();
    }

    @Timed(value = "silicaproxy.dao.upstreamhead.cache.deleteexpired",
            description = "Duration of expired upstream HEAD cache deletion",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public int deleteExpired() {
        return jdbcClient.sql("""
                DELETE FROM upstream_head_cache
                WHERE expires_at <= CURRENT_TIMESTAMP
                """)
                .update();
    }
}
