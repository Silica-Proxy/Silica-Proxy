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

import com.silicaproxy.model.dto.ApiCacheHit;
import com.silicaproxy.model.dto.PublicVulnerabilityRow;
import com.silicaproxy.model.entity.CompanyPolicy;
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Repository
@NullMarked
public class PackageSearchDao {

    private final JdbcClient jdbcClient;

    public PackageSearchDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Timed(value = "silicaproxy.dao.packagesearch.searchcompanypolicies",
            description = "Duration of searching company policies",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public List<CompanyPolicy> searchCompanyPolicies(
            String packageName, @Nullable String ecosystem, @Nullable String exactVersion, @Nullable String versionRegex) {
        StringBuilder sql = new StringBuilder("""
                SELECT package_name AS "packageName", ecosystem,
                       version_pattern AS "versionPattern", policy_action AS "policyAction",
                       reason, updated_by AS "updatedBy"
                FROM company_policies
                WHERE package_name = :packageName
                """);
        if (ecosystem != null) {
            sql.append(" AND ecosystem = :ecosystem");
        }
        if (exactVersion != null) {
            // The stored pattern contains SQL wildcards ('%') already translated from 'x'/'*' during GitOps ingestion.
            // '_' and '\' are literal version characters there, so they are escaped (same as DecisionDao).
            sql.append(" AND :exactVersion LIKE REPLACE(REPLACE(version_pattern, '\\', '\\\\'), '_', '\\_') ESCAPE '\\'");
        }
        if (versionRegex != null) {
            sql.append(" AND version_pattern ~ :versionRegex");
        }

        JdbcClient.StatementSpec spec = jdbcClient.sql(sql.toString()).param("packageName", packageName);
        if (ecosystem != null) {
            spec = spec.param("ecosystem", ecosystem);
        }
        if (exactVersion != null) {
            spec = spec.param("exactVersion", exactVersion);
        }
        if (versionRegex != null) {
            spec = spec.param("versionRegex", versionRegex);
        }

        return spec.query(CompanyPolicy.class).list();
    }

    // Every advisory of the package. The regex is evaluated here by PostgreSQL, like the other searches,
    // so that no user-supplied pattern runs in the JVM : with a regex, versions_json only holds the
    // matching enumerated versions, and range-only advisories (npm/Maven, affected_versions = []) are
    // kept since a regex cannot be tested against a range. Exact-version filtering, which needs
    // OsvRangeEvaluator, is left to PackageSearchService.
    @Timed(value = "silicaproxy.dao.packagesearch.findpublicvulnerabilities",
            description = "Duration of searching public vulnerabilities",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public List<PublicVulnerabilityRow> findPublicVulnerabilities(
            String packageName, @Nullable String ecosystem, @Nullable String exactVersion, @Nullable String versionRegex) {
        String versionsColumn = versionRegex != null
                ? """
                  COALESCE((SELECT jsonb_agg(v) FROM jsonb_array_elements_text(affected_versions) AS v
                            WHERE v ~ :versionRegex), '[]'::jsonb)::text"""
                : "affected_versions::text";
        StringBuilder sql = new StringBuilder("SELECT id, source, package_name, ecosystem, summary, "
                + "COALESCE(cvss_score, inherited_cvss_score) AS cvss_score, published_at, "
                + versionsColumn + """
                 AS versions_json, affected_ranges::text AS ranges_json
                FROM public_vulnerabilities
                WHERE package_name = :packageName
                """);
        if (ecosystem != null) {
            sql.append(" AND ecosystem = :ecosystem");
        }
        if (versionRegex != null && exactVersion != null) {
            sql.append(" AND :exactVersion ~ :versionRegex");
        } else if (versionRegex != null) {
            sql.append("""
                     AND (EXISTS (SELECT 1 FROM jsonb_array_elements_text(affected_versions) AS v WHERE v ~ :versionRegex)
                          OR (jsonb_array_length(affected_versions) = 0 AND jsonb_array_length(affected_ranges) > 0))
                    """);
        }

        JdbcClient.StatementSpec spec = jdbcClient.sql(sql.toString()).param("packageName", packageName);
        if (ecosystem != null) {
            spec = spec.param("ecosystem", ecosystem);
        }
        if (versionRegex != null) {
            spec = spec.param("versionRegex", versionRegex);
            if (exactVersion != null) {
                spec = spec.param("exactVersion", exactVersion);
            }
        }
        List<PublicVulnerabilityRow> rows = new ArrayList<>();
        for (Map<String, Object> row : spec.query().listOfRows()) {
            rows.add(mapVulnRow(row));
        }
        return rows;
    }

    private static PublicVulnerabilityRow mapVulnRow(Map<String, Object> row) {
        Timestamp publishedTs = (Timestamp) row.get("published_at");
        Number cvssScore = (Number) row.get("cvss_score");
        return new PublicVulnerabilityRow(
                (String) row.get("id"),
                (String) row.get("source"),
                (String) row.get("package_name"),
                (String) row.get("ecosystem"),
                (String) row.get("summary"),
                cvssScore != null ? cvssScore.doubleValue() : null,
                publishedTs != null ? publishedTs.toInstant() : null,
                (String) row.get("versions_json"),
                (String) row.get("ranges_json")
        );
    }

    @Timed(value = "silicaproxy.dao.packagesearch.searchapicache",
            description = "Duration of searching the API verdict cache",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public List<ApiCacheHit> searchApiCache(
            String packageName, @Nullable String ecosystem, @Nullable String exactVersion, @Nullable String versionRegex) {
        StringBuilder sql = new StringBuilder("""
                SELECT package_name AS "packageName", ecosystem,
                       package_version AS "version", is_secure AS "isSecure",
                       api_source AS "apiSource", expires_at AS "expiresAt",
                       (expires_at <= CURRENT_TIMESTAMP) AS "expired"
                FROM api_cache
                WHERE package_name = :packageName
                """);
        if (ecosystem != null) {
            sql.append(" AND ecosystem = :ecosystem");
        }
        if (exactVersion != null) {
            sql.append(" AND package_version = :exactVersion");
        }
        if (versionRegex != null) {
            sql.append(" AND package_version ~ :versionRegex");
        }

        JdbcClient.StatementSpec spec = jdbcClient.sql(sql.toString()).param("packageName", packageName);
        if (ecosystem != null) {
            spec = spec.param("ecosystem", ecosystem);
        }
        if (exactVersion != null) {
            spec = spec.param("exactVersion", exactVersion);
        }
        if (versionRegex != null) {
            spec = spec.param("versionRegex", versionRegex);
        }

        return spec.query(ApiCacheHit.class).list();
    }
}
