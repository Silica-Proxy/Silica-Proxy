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
import com.silicaproxy.model.dto.PublicVulnerabilityHit;
import com.silicaproxy.model.entity.CompanyPolicy;
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
            sql.append(" AND :exactVersion LIKE version_pattern");
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

    public List<PublicVulnerabilityHit> searchPublicVulnerabilities(
            String packageName, @Nullable String ecosystem, @Nullable String exactVersion, @Nullable String versionRegex) {
        JdbcClient.StatementSpec spec = buildVulnSpec(packageName, ecosystem, exactVersion, versionRegex);
        List<Map<String, Object>> rows = spec.query().listOfRows();
        List<PublicVulnerabilityHit> hits = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            hits.add(mapVulnRow(row));
        }
        return hits;
    }

    private JdbcClient.StatementSpec buildVulnSpec(
            String packageName, @Nullable String ecosystem, @Nullable String exactVersion, @Nullable String versionRegex) {
        StringBuilder sql = new StringBuilder("""
                SELECT pv.id, pv.source, pv.package_name AS package_name, pv.ecosystem, pv.summary,
                       pv.cvss_score, pv.published_at, array_agg(elem.value) AS matched_versions
                FROM public_vulnerabilities pv
                CROSS JOIN LATERAL jsonb_array_elements_text(pv.affected_versions) AS elem(value)
                WHERE pv.package_name = :packageName
                """);
        if (ecosystem != null) {
            sql.append(" AND pv.ecosystem = :ecosystem");
        }
        if (exactVersion != null) {
            sql.append(" AND elem.value = :exactVersion");
        }
        if (versionRegex != null) {
            sql.append(" AND elem.value ~ :versionRegex");
        }
        sql.append(" GROUP BY pv.id, pv.source, pv.package_name, pv.ecosystem, pv.summary, pv.cvss_score, pv.published_at");

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
        return spec;
    }

    private static PublicVulnerabilityHit mapVulnRow(Map<String, Object> row) {
        Timestamp publishedTs = (Timestamp) row.get("published_at");
        java.sql.Array matchedArray = (java.sql.Array) row.get("matched_versions");
        List<String> matchedVersions = extractStringArray(matchedArray);
        return new PublicVulnerabilityHit(
                (String) row.get("id"),
                (String) row.get("source"),
                (String) row.get("package_name"),
                (String) row.get("ecosystem"),
                (String) row.get("summary"),
                ((Number) row.get("cvss_score")).doubleValue(),
                publishedTs != null ? publishedTs.toInstant() : null,
                matchedVersions
        );
    }

    private static List<String> extractStringArray(java.sql.@Nullable Array sqlArray) {
        if (sqlArray == null) {
            return List.of();
        }
        try {
            return List.of((String[]) sqlArray.getArray());
        } catch (java.sql.SQLException e) {
            return List.of();
        }
    }

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
