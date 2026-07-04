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

import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import io.micrometer.core.annotation.Timed;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * Persists and cleans the two L2 caches used to avoid re-contact with external registries/APIs :
 * {@code package_metadata} (publication date, immutable, never expires) and {@code api_cache}
 * (security verdict, TTL 24h or infinite if deprecated). Called by {@code SecurityService} at
 * each resolution of a package missing from local tables during decision evaluation,
 * and by {@code ApiCacheCleanupService} for purging expired entries.
 */
@Repository
@NullMarked
public class MetadataCacheDao {

    private final JdbcClient jdbcClient;

    public MetadataCacheDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Timed(value = "silicaproxy.dao.metadatacache.getpackagepublishedat",
            description = "Duration of retrieving package publication date from cache",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<Instant> getPackagePublishedAt(String packageName, String ecosystem, String version) {
        String sql = """
            SELECT published_at
            FROM package_metadata
            WHERE package_name = :packageName
              AND ecosystem = :ecosystem
              AND package_version = :version
            """;
        return jdbcClient.sql(sql)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem.toLowerCase())
                .param("version", version)
                .query(Timestamp.class)
                .optional()
                .map(Timestamp::toInstant);
    }

    @Timed(value = "silicaproxy.dao.metadatacache.savepackagepublishedat",
            description = "Duration of saving package publication date to cache",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void savePackagePublishedAt(String packageName, String ecosystem, String version, Instant publishedAt) {
        String sql = """
            INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
            VALUES (:packageName, :ecosystem, :version, :publishedAt)
            ON CONFLICT (package_name, ecosystem, package_version) DO NOTHING
            """;
        jdbcClient.sql(sql)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem.toLowerCase())
                .param("version", version)
                .param("publishedAt", Timestamp.from(publishedAt))
                .update();
    }

    @Timed(value = "silicaproxy.dao.metadatacache.saveapicache",
            description = "Duration of saving API verdict to L2 cache",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void saveApiCache(
            String packageName, 
            String ecosystem, 
            String version, 
            boolean isSecure, 
            String apiSource, 
            Instant expiresAt) {
        String sql = """
            INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
            VALUES (:packageName, :ecosystem, :version, :isSecure, :apiSource, :expiresAt)
            ON CONFLICT (package_name, ecosystem, package_version) DO UPDATE SET
                is_secure = EXCLUDED.is_secure,
                api_source = EXCLUDED.api_source,
                expires_at = EXCLUDED.expires_at
            """;
        jdbcClient.sql(sql)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem.toLowerCase())
                .param("version", version)
                .param("isSecure", isSecure)
                .param("apiSource", apiSource)
                .param("expiresAt", Timestamp.from(expiresAt))
                .update();
    }

    @Transactional
    public int deleteExpiredApiCache() {
        return jdbcClient.sql("DELETE FROM api_cache WHERE expires_at <= CURRENT_TIMESTAMP").update();
    }
}
