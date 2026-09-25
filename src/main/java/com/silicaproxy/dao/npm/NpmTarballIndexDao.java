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


package com.silicaproxy.dao.npm;

import com.silicaproxy.model.dto.PackageMetadataResult;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * Persistence of npm tarball identification index in PostgreSQL, shared by all proxy instances.
 * Populated when a packument is relayed (to index tarballs and their metadata) ;
 * consulted when a tarball request arrives on another instance (multi-instance cache hit).
 * Rows expire after a configurable TTL (typically 60 minutes).
 */
@Repository
@NullMarked
public class NpmTarballIndexDao {

    private final JdbcClient jdbcClient;

    public NpmTarballIndexDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public record NpmTarballEntry(
            String tarballUrl,
            String packageName,
            String packageVersion,
            @Nullable Instant publishedAt,
            boolean deprecated,
            @Nullable String deprecationReason,
            String packumentUrl
    ) {}

    /**
     * Remembers a tarball URL and its package/version/metadata. Expires after the TTL.
     */
    public void save(String tarballUrl, String packageName, String packageVersion,
                     @Nullable Instant publishedAt, boolean deprecated, @Nullable String deprecationReason,
                     String packumentUrl, Instant expiresAt) {
        jdbcClient.sql(
                "INSERT INTO npm_tarball_index " +
                "(tarball_url, package_name, package_version, published_at, deprecated, deprecation_reason, packument_url, expires_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
                "ON CONFLICT (tarball_url) DO UPDATE SET " +
                "  package_name = EXCLUDED.package_name, " +
                "  published_at = EXCLUDED.published_at, " +
                "  deprecated = EXCLUDED.deprecated, " +
                "  deprecation_reason = EXCLUDED.deprecation_reason, " +
                "  packument_url = EXCLUDED.packument_url, " +
                "  indexed_at = NOW(), " +
                "  expires_at = EXCLUDED.expires_at"
        )
                .param(tarballUrl)
                .param(packageName)
                .param(packageVersion)
                .param(publishedAt != null ? Timestamp.from(publishedAt) : null)
                .param(deprecated)
                .param(deprecationReason)
                .param(packumentUrl)
                .param(Timestamp.from(expiresAt))
                .update();
    }

    /**
     * Resolves a tarball URL previously indexed: package name, version, and metadata.
     * Returns empty if not found or expired.
     */
    public Optional<NpmTarballEntry> findByUrl(String tarballUrl) {
        return jdbcClient.sql(
                "SELECT tarball_url, package_name, package_version, published_at, " +
                "       deprecated, deprecation_reason, packument_url " +
                "FROM npm_tarball_index " +
                "WHERE tarball_url = ? AND expires_at > NOW()"
        )
                .param(tarballUrl)
                .query((rs, rowNum) -> new NpmTarballEntry(
                        rs.getString("tarball_url"),
                        rs.getString("package_name"),
                        rs.getString("package_version"),
                        toInstant(rs.getTimestamp("published_at")),
                        rs.getBoolean("deprecated"),
                        rs.getString("deprecation_reason"),
                        rs.getString("packument_url")
                ))
                .optional();
    }

    /**
     * Queries by package@version (fallback when tarball URL layout is not recognized).
     * Returns the metadata if found and not expired.
     */
    public Optional<PackageMetadataResult> findMetadataByPackage(String packageName, String packageVersion) {
        return jdbcClient.sql(
                "SELECT published_at, deprecated, deprecation_reason " +
                "FROM npm_tarball_index " +
                "WHERE package_name = ? AND package_version = ? AND expires_at > NOW() " +
                "  AND published_at IS NOT NULL " +
                "LIMIT 1"
        )
                .param(packageName)
                .param(packageVersion)
                .query((rs, rowNum) -> new PackageMetadataResult(
                        // never null : filtered by "published_at IS NOT NULL" above
                        rs.getTimestamp("published_at").toInstant(),
                        rs.getBoolean("deprecated"),
                        rs.getString("deprecation_reason")
                ))
                .optional();
    }

    /**
     * Origin packument URL for a package@version, if known. Used by SecurityService to query
     * the origin registry's full packument when the abbreviated one lacked "time".
     */
    public Optional<String> findPackumentUrl(String packageName, String packageVersion) {
        return jdbcClient.sql(
                "SELECT packument_url FROM npm_tarball_index " +
                "WHERE package_name = ? AND package_version = ? " +
                "  AND packument_url != '' AND expires_at > NOW() " +
                "LIMIT 1"
        )
                .param(packageName)
                .param(packageVersion)
                .query(String.class)
                .optional();
    }

    private static @Nullable Instant toInstant(@Nullable Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }

    /**
     * Evicts entries that have expired (past the expires_at timestamp).
     * Called by a scheduled cleanup job (see NpmTarballIndexCleanupService).
     */
    public int evictExpired() {
        return jdbcClient.sql("DELETE FROM npm_tarball_index WHERE expires_at <= NOW()")
                .update();
    }

    /**
     * Current count of non-expired entries (for monitoring).
     */
    public int count() {
        return jdbcClient.sql("SELECT COUNT(*) FROM npm_tarball_index WHERE expires_at > NOW()")
                .query(Integer.class)
                .single();
    }
}
