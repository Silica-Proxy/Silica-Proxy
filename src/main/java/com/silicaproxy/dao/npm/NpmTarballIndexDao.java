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
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
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

    private static final int BATCH_SIZE = 500;

    private static final String UPSERT_SQL =
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
            "  expires_at = EXCLUDED.expires_at";

    private final JdbcClient jdbcClient;
    private final JdbcTemplate jdbcTemplate;

    public NpmTarballIndexDao(JdbcClient jdbcClient, JdbcTemplate jdbcTemplate) {
        this.jdbcClient = jdbcClient;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * A row to persist : the entry, the instant its row expires, and whether other instances need
     * it to identify the tarball (its URL carries no package/version, so without the row it would
     * go unidentified).
     */
    public record PendingEntry(NpmTarballEntry entry, Instant expiresAt, boolean requiredForIdentification) {}

    /**
     * Upserts many entries in JDBC batches : a large packument (thousands of versions) costs a few
     * round trips instead of one per version.
     */
    @Timed(value = "silicaproxy.dao.npmtarballindex.saveall",
            description = "Duration of batch indexing npm tarball URLs",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void saveAll(List<PendingEntry> entries) {
        for (int from = 0; from < entries.size(); from += BATCH_SIZE) {
            List<PendingEntry> chunk = entries.subList(from, Math.min(from + BATCH_SIZE, entries.size()));
            jdbcTemplate.batchUpdate(UPSERT_SQL, chunk, chunk.size(), (ps, pending) -> {
                NpmTarballEntry e = pending.entry();
                ps.setString(1, e.tarballUrl());
                ps.setString(2, e.packageName());
                ps.setString(3, e.packageVersion());
                ps.setTimestamp(4, e.publishedAt() != null ? Timestamp.from(e.publishedAt()) : null);
                ps.setBoolean(5, e.deprecated());
                ps.setString(6, e.deprecationReason());
                ps.setString(7, e.packumentUrl());
                ps.setTimestamp(8, Timestamp.from(pending.expiresAt()));
            });
        }
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
    @Timed(value = "silicaproxy.dao.npmtarballindex.save",
            description = "Duration of indexing an npm tarball URL",
            percentiles = {0.5, 0.9, 0.95, 0.99})
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
    @Timed(value = "silicaproxy.dao.npmtarballindex.findbyurl",
            description = "Duration of looking up an npm tarball by URL",
            percentiles = {0.5, 0.9, 0.95, 0.99})
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
    @Timed(value = "silicaproxy.dao.npmtarballindex.findmetadatabypackage",
            description = "Duration of looking up indexed npm metadata by package version",
            percentiles = {0.5, 0.9, 0.95, 0.99})
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
    @Timed(value = "silicaproxy.dao.npmtarballindex.findpackumenturl",
            description = "Duration of looking up the packument URL of an npm package version",
            percentiles = {0.5, 0.9, 0.95, 0.99})
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
    @Timed(value = "silicaproxy.dao.npmtarballindex.evictexpired",
            description = "Duration of evicting expired npm tarball index entries",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public int evictExpired() {
        return jdbcClient.sql("DELETE FROM npm_tarball_index WHERE expires_at <= NOW()")
                .update();
    }

    /**
     * Current count of non-expired entries (for monitoring).
     */
    @Timed(value = "silicaproxy.dao.npmtarballindex.count",
            description = "Duration of counting npm tarball index entries",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public int count() {
        return jdbcClient.sql("SELECT COUNT(*) FROM npm_tarball_index WHERE expires_at > NOW()")
                .query(Integer.class)
                .single();
    }
}
