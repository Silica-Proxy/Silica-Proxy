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
import com.silicaproxy.model.dto.RangeCandidate;
import com.silicaproxy.model.dto.SeverityThreshold;
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
 * public vulnerabilities, API cache) to return only one verdict, plus a second indexed lookup
 * of the OSV version ranges ({@link #findRangeCandidates}) evaluated in Java at the public
 * vulnerability priority. Called by {@code SecurityService.getDecision()} at each incoming
 * proxy request, before any external network call.
 */
@Repository
@NullMarked
public class DecisionDao {

    // Severity threshold on a public_vulnerabilities row, shared by evaluateDecision and
    // findRangeCandidates (see SeverityThreshold) : the row's own score, or the one it inherits
    // from its aliases when it has none (VulnerabilityDao.refreshInheritedScores) ; no score at
    // all is an unknown severity, blocked when :blockUnknown. Malwares (MAL-/OPENSSF) are always
    // blocked : they usually carry no score.
    private static final String SEVERITY_PREDICATE = "(" + malwarePredicate("id", "source") + """

                   OR COALESCE(cvss_score, inherited_cvss_score) > :maxAllowedCvss::numeric
                   OR COALESCE(cvss_score, inherited_cvss_score) >= :severityFloor::numeric
                   OR (:blockUnknown::boolean AND cvss_score IS NULL AND inherited_cvss_score IS NULL))
            """;

    // Malware advisory (MAL- id or OpenSSF source), on the given id/source columns : shared by
    // SEVERITY_PREDICATE, the PUBLIC_VULN_MALWARE source type and the anomaly branch, so a
    // malware is recognised the same way wherever it is matched. Parenthesized because a text
    // block strips the trailing space before it (e.g. "CASE WHEN """ + ...).
    private static String malwarePredicate(String idColumn, String sourceColumn) {
        return "(" + idColumn + " LIKE 'MAL-%' OR " + sourceColumn + " = 'OPENSSF')";
    }

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
            SeverityThreshold threshold) {
        
        String sql = """
            WITH checked_package AS (
                SELECT 
                    :packageName::varchar AS p_name, 
                    :packageVersion::varchar AS p_version, 
                    :ecosystem::varchar AS p_ecosystem
            )
            SELECT source_type AS "sourceType", result, reason FROM (
                -- PRIORITY 1 : Company allow or block rules (company_policies)
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
                       'COMPANY_POLICY' AS source_type,
                       -- Mapped onto the Verdict enum : ALLOW and BLOCK are kept as is, anything
                       -- else fails closed as a BLOCK.
                       CASE WHEN policy_action = 'ALLOW' THEN 'ALLOW' ELSE 'BLOCK' END AS result,
                       reason
                FROM company_policies, checked_package
                WHERE p_name LIKE
                      REPLACE(REPLACE(REPLACE(package_name, '_', '\\_'), '%', '\\%'), '*', '%') ESCAPE '\\'
                  AND ecosystem = p_ecosystem
                  -- version_pattern is already stored '%'-translated by GitOpsSyncService at
                  -- write time (see toSqlWildcardPattern) : re-translating '*'/'x' here again
                  -- would be redundant. '%' is the only intended wildcard in it : '_' (and '\\')
                  -- are literal version characters, escaped here so that a rule for
                  -- "1.0.0_rc1" does not also match "1.0.0-rc1".
                  AND p_version LIKE REPLACE(REPLACE(version_pattern, '\\', '\\\\'), '_', '\\_') ESCAPE '\\'

                UNION ALL

                -- PRIORITY 2 : Known public security vulnerability (public_vulnerabilities)
                -- source_type distinguishes a malware verdict (always blocked regardless of CVSS)
                -- from a plain CVSS-threshold block, so downstream metrics/dashboards can tell a
                -- genuine malware detection apart from a severity-policy call.
                SELECT 2 AS priority, 0 AS specificity,
                       CASE WHEN """ + malwarePredicate("id", "source") + """
                             THEN 'PUBLIC_VULN_MALWARE' ELSE 'PUBLIC_VULN' END AS source_type,
                       'BLOCK' AS result, summary AS reason
                FROM public_vulnerabilities, checked_package
                WHERE package_name = p_name
                  AND ecosystem = p_ecosystem
                  AND affected_versions @> jsonb_build_array(p_version)
                  AND """ + SEVERITY_PREDICATE + """

                UNION ALL

                -- PRIORITY 2 (same tier as PUBLIC_VULN) : vulnerability_ingestion_anomalies.
                -- Some upstream OSV advisories for multi-ecosystem monorepos flatten a
                -- DIFFERENT package's identifier into one ecosystem's "versions" list (see
                -- gradio PYSEC-2023-255/2024-184: "@gradio/chatbot@0.4.2", an npm sub-package,
                -- listed inside the PyPI "gradio" advisory). package_name/ecosystem on this row
                -- reflect that WRONG outer advisory, not the embedded package, so we deliberately
                -- do NOT filter on them here -- only suspicious_version, matched as a literal
                -- "name@version" string against the actual request, carries the real signal.
                -- Like PUBLIC_VULN, an anomaly of a malware advisory is always blocked and
                -- reported as PUBLIC_VULN_MALWARE.
                SELECT 2 AS priority, 0 AS specificity,
                       CASE WHEN """ + malwarePredicate("anomaly.vulnerability_id", "anomaly.source") + """
                             THEN 'PUBLIC_VULN_MALWARE' ELSE 'PUBLIC_VULN_ANOMALY' END AS source_type,
                       'BLOCK' AS result,
                       'Data-quality anomaly during OSV ingestion: this exact package/version was '
                       || 'listed as affected inside advisory ' || vulnerability_id AS reason
                -- Same threshold as PUBLIC_VULN, on the anomaly's own score or, when it has none,
                -- on the (possibly inherited) score of its advisory ; malwares bypass it.
                FROM vulnerability_ingestion_anomalies anomaly
                CROSS JOIN checked_package
                CROSS JOIN LATERAL (
                    SELECT COALESCE(anomaly.cvss_score, MAX(COALESCE(pv.cvss_score, pv.inherited_cvss_score))) AS score
                    FROM public_vulnerabilities pv
                    WHERE pv.id = anomaly.vulnerability_id
                ) advisory
                WHERE suspicious_version = p_name || '@' || p_version
                  AND (""" + malwarePredicate("anomaly.vulnerability_id", "anomaly.source") + """

                       OR advisory.score > :maxAllowedCvss::numeric
                       OR advisory.score >= :severityFloor::numeric
                       OR (:blockUnknown::boolean AND advisory.score IS NULL))

                UNION ALL

                -- PRIORITY 3 : External API analysis cache (api_cache)
                SELECT 3 AS priority, 0 AS specificity, 'API_CACHE' AS source_type,
                       CASE WHEN is_secure THEN 'ALLOW' ELSE 'BLOCK' END AS result,
                       CASE WHEN is_secure THEN 'Validated via API cache'
                            ELSE 'Blocked by cached ' || COALESCE(api_source, 'API') || ' verdict'
                                 || COALESCE(': ' || (SELECT string_agg(vuln_id, ', ')
                                                      FROM jsonb_array_elements_text(scan_details -> 'vulnerabilityIds') AS vuln_id), '')
                       END AS reason
                FROM api_cache, checked_package
                WHERE package_name = p_name AND ecosystem = p_ecosystem
                  AND package_version = p_version AND expires_at > CURRENT_TIMESTAMP
            ) AS combined_results
            -- Tie-break when two rows share the same priority and specificity (e.g. two
            -- company_policies rows for the same package/version/ecosystem, one ALLOW and
            -- one BLOCK) : the most restrictive result wins, rather than an arbitrary row
            -- order.
            ORDER BY priority ASC, specificity ASC,
                     CASE WHEN result = 'BLOCK' THEN 0 ELSE 1 END ASC
            LIMIT 1;
            """;

        return jdbcClient.sql(sql)
                .param("packageName", packageName)
                .param("packageVersion", packageVersion)
                .param("ecosystem", ecosystem)
                .param("maxAllowedCvss", threshold.maxAllowedCvss())
                .param("severityFloor", threshold.severityFloor())
                .param("blockUnknown", threshold.blockUnknown())
                .query(DecisionResult.class)
                .optional();
    }

    // Second local lookup, run only when evaluateDecision() found neither a company policy nor
    // an enumerated public vulnerability : rows whose OSV ranges must be evaluated in Java
    // (OsvRangeEvaluator), npm advisories carrying no version list at all. Same CVSS/malware
    // filter as the PRIORITY 2 branch of evaluateDecision().
    @Timed(value = "silicaproxy.dao.decision.findrangecandidates",
            description = "Duration of the OSV range candidates lookup in DecisionDao",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public List<RangeCandidate> findRangeCandidates(String packageName, String ecosystem, SeverityThreshold threshold) {
        return jdbcClient.sql("""
                SELECT id, source, summary, affected_ranges::text AS "rangesJson"
                FROM public_vulnerabilities
                WHERE package_name = :packageName AND ecosystem = :ecosystem
                  AND affected_ranges <> '[]'::jsonb
                  AND """ + SEVERITY_PREDICATE)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("maxAllowedCvss", threshold.maxAllowedCvss())
                .param("severityFloor", threshold.severityFloor())
                .param("blockUnknown", threshold.blockUnknown())
                .query(RangeCandidate.class)
                .list();
    }
}
