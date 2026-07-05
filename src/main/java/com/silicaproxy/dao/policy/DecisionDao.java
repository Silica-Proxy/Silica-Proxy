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

import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.entity.SeverityMapping;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import io.micrometer.core.annotation.Timed;

import java.util.List;
import java.util.Optional;

/**
 * SQL core of the proxy decision  : a single query combining with 
 * {@code UNION ALL}/{@code ORDER BY priority} the three local sources (company policies, 
 * public vulnerabilities, API cache) to return only one verdict. Called by 
 * {@code SecurityService.getDecision()} at each incoming proxy request, before any 
 * external network call.
 */
@Repository
@NullMarked
public class DecisionDao {

    private final JdbcClient jdbcClient;

    public DecisionDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public List<SeverityMapping> findAllSeverityMappings() {
        return jdbcClient.sql("""
                SELECT severity_level AS "severityLevel", min_cvss AS "minCvss", max_cvss AS "maxCvss"
                FROM severity_mappings
                """)
                .query(SeverityMapping.class)
                .list();
    }

    @Timed(value = "silicaproxy.dao.decision.evaluatedecision",
            description = "Duration of evaluating the unique SQL decision in DecisionDao",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<DecisionResult> evaluateDecision(
            String packageName, 
            String packageVersion, 
            String ecosystem, 
            double minCvssScore) {
        
        String sql = """
            WITH checked_package AS (
                SELECT 
                    :packageName::varchar AS p_name, 
                    :packageVersion::varchar AS p_version, 
                    :ecosystem::varchar AS p_ecosystem
            )
            SELECT source_type AS "sourceType", result, reason FROM (
                -- PRIORITY 1 : Company whitelist or blacklist (company_policies)
                -- package_name may itself be a '*' wildcard pattern (e.g. "@Toto/Titi*"), but
                -- 'x' is NOT a wildcard here (unlike version_pattern) : real package names
                -- commonly contain the literal letter 'x' (axios, next, xml2js...).
                -- specificity : exact package name always beats a wildcard package pattern ;
                -- an exact version is then used as a tie-breaker over a wildcard version, so
                -- an explicit rule for 1.0.0 always overrides a generic * rule for the same
                -- package.
                SELECT 1 AS priority,
                       CASE WHEN package_name = p_name THEN 0 ELSE 2 END
                           + CASE WHEN version_pattern = p_version THEN 0 ELSE 1 END AS specificity,
                       'COMPANY_POLICY' AS source_type, policy_action AS result, reason
                FROM company_policies, checked_package
                WHERE p_name LIKE
                      REPLACE(REPLACE(REPLACE(package_name, '_', '\\_'), '%', '\\%'), '*', '%') ESCAPE '\\'
                  AND ecosystem = p_ecosystem
                  -- version_pattern is already stored '%'-translated by GitOpsSyncService at
                  -- write time (see toSqlWildcardPattern) : re-translating '*'/'x' here again
                  -- would be redundant.
                  AND p_version LIKE version_pattern

                UNION ALL

                -- PRIORITY 2 : Known public security vulnerability (public_vulnerabilities)
                -- source_type distinguishes a malware verdict (always blocked regardless of CVSS)
                -- from a plain CVSS-threshold block, so downstream metrics/dashboards can tell a
                -- genuine malware detection apart from a severity-policy call.
                SELECT 2 AS priority, 0 AS specificity,
                       CASE WHEN id LIKE 'MAL-%' OR source = 'OPENSSF' THEN 'PUBLIC_VULN_MALWARE'
                            ELSE 'PUBLIC_VULN' END AS source_type,
                       'BLOCK' AS result, summary AS reason
                FROM public_vulnerabilities, checked_package
                WHERE package_name = p_name
                  AND ecosystem = p_ecosystem
                  AND affected_versions @> jsonb_build_array(p_version)
                  -- Malwares (MAL-/OPENSSF) always blocked : their CVSS score is 0.0 by default
                  AND (cvss_score >= :minCvss::numeric OR id LIKE 'MAL-%' OR source = 'OPENSSF')

                UNION ALL

                -- PRIORITY 2 (same tier as PUBLIC_VULN) : vulnerability_ingestion_anomalies.
                -- Some upstream OSV advisories for multi-ecosystem monorepos flatten a
                -- DIFFERENT package's identifier into one ecosystem's "versions" list (see
                -- gradio PYSEC-2023-255/2024-184: "@gradio/chatbot@0.4.2", an npm sub-package,
                -- listed inside the PyPI "gradio" advisory). package_name/ecosystem on this row
                -- reflect that WRONG outer advisory, not the embedded package, so we deliberately
                -- do NOT filter on them here -- only suspicious_version, matched as a literal
                -- "name@version" string against the actual request, carries the real signal.
                SELECT 2 AS priority, 0 AS specificity,
                       'PUBLIC_VULN_ANOMALY' AS source_type, 'BLOCK' AS result,
                       'Data-quality anomaly during OSV ingestion: this exact package/version was '
                       || 'listed as affected inside advisory ' || vulnerability_id AS reason
                FROM vulnerability_ingestion_anomalies, checked_package
                WHERE suspicious_version = p_name || '@' || p_version
                  AND cvss_score >= :minCvss::numeric

                UNION ALL

                -- PRIORITY 3 : External API analysis cache (api_cache)
                SELECT 3 AS priority, 0 AS specificity, 'API_CACHE' AS source_type,
                       CASE WHEN is_secure THEN 'ALLOW' ELSE 'BLOCK' END AS result,
                       'Validated via API cache' AS reason
                FROM api_cache, checked_package
                WHERE package_name = p_name AND ecosystem = p_ecosystem
                  AND package_version = p_version AND expires_at > CURRENT_TIMESTAMP
            ) AS combined_results
            -- Tie-break when two rows share the same priority and specificity (e.g. two
            -- company_policies rows for the same package/version/ecosystem, one WHITELIST and
            -- one BLACKLIST) : the most restrictive result wins, rather than an arbitrary row
            -- order.
            ORDER BY priority ASC, specificity ASC,
                     CASE WHEN result IN ('BLOCK', 'BLACKLIST') THEN 0 ELSE 1 END ASC
            LIMIT 1;
            """;

        return jdbcClient.sql(sql)
                .param("packageName", packageName)
                .param("packageVersion", packageVersion)
                .param("ecosystem", ecosystem)
                .param("minCvss", minCvssScore)
                .query(DecisionResult.class)
                .optional();
    }
}
