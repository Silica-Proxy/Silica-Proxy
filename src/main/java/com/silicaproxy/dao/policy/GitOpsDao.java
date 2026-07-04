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

import com.silicaproxy.model.dto.MatchedPolicyDto;
import com.silicaproxy.model.entity.CompanyPolicy;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Atomically replaces the {@code company_policies} rules for an ecosystem (DELETE then 
 * batch upsert). Called by {@code GitOpsSyncService} at each scheduled 
 * GitOps synchronization cycle ({@code sync-interval-minutes}) or manually triggered.
 */
@Repository
@NullMarked
public class GitOpsDao {

    private static final int MAX_BATCH_SIZE = 500;

    private final JdbcClient jdbcClient;

    public GitOpsDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Map<String, Long> countPoliciesByEcosystem() {
        List<Map<String, Object>> rows = jdbcClient.sql(
                "SELECT ecosystem, count(*) AS cnt FROM company_policies GROUP BY ecosystem ORDER BY ecosystem")
                .query()
                .listOfRows();

        Map<String, Long> result = new LinkedHashMap<>();
        for (Map<String, Object> row : rows) {
            result.put((String) row.get("ecosystem"), ((Number) row.get("cnt")).longValue());
        }
        return result;
    }

    @Transactional
    public void replaceCompanyPolicies(String ecosystem, List<CompanyPolicy> policies) {
        jdbcClient.sql("DELETE FROM company_policies WHERE ecosystem = :ecosystem")
                .param("ecosystem", ecosystem)
                .update();

        for (int start = 0; start < policies.size(); start += MAX_BATCH_SIZE) {
            List<CompanyPolicy> chunk = policies.subList(start, Math.min(start + MAX_BATCH_SIZE, policies.size()));
            insertChunk(ecosystem, chunk);
        }
    }

    private void insertChunk(String ecosystem, List<CompanyPolicy> chunk) {
        StringBuilder valuesClause = new StringBuilder();
        for (int i = 0; i < chunk.size(); i++) {
            if (i > 0) {
                valuesClause.append(",\n");
            }
            valuesClause.append("(:packageName").append(i)
                    .append(", :ecosystem").append(i)
                    .append(", :versionPattern").append(i)
                    .append(", :policyAction").append(i)
                    .append(", :reason").append(i)
                    .append(", :updatedBy").append(i)
                    .append(")");
        }

        String sql = """
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES
            """
            + valuesClause;

        JdbcClient.StatementSpec statement = jdbcClient.sql(sql);
        for (int i = 0; i < chunk.size(); i++) {
            CompanyPolicy policy = chunk.get(i);
            statement = statement
                    .param("packageName" + i, policy.packageName())
                    .param("ecosystem" + i, ecosystem)
                    .param("versionPattern" + i, policy.versionPattern())
                    .param("policyAction" + i, policy.policyAction())
                    .param("reason" + i, policy.reason())
                    .param("updatedBy" + i, policy.updatedBy());
        }
        statement.update();
    }

    // Returns all company_policies rules matching the package/version/ecosystem, sorted by
    // specificity (exact package beats wildcard package, exact version beats wildcard version),
    // to visualize conflict resolution.
    public List<MatchedPolicyDto> findMatchingPolicies(String packageName, String version, String ecosystem) {
        return jdbcClient.sql("""
                SELECT package_name AS "packageName",
                       version_pattern AS "versionPattern",
                       policy_action AS "policyAction",
                       reason,
                       CASE WHEN package_name = :packageName THEN 0 ELSE 2 END
                           + CASE WHEN version_pattern = :version THEN 0 ELSE 1 END AS specificity,
                       false AS wins
                FROM company_policies
                WHERE :packageName LIKE
                      REPLACE(REPLACE(REPLACE(package_name, '_', '\\_'), '%', '\\%'), '*', '%') ESCAPE '\\'
                  AND ecosystem = :ecosystem
                  AND :version LIKE REPLACE(REPLACE(version_pattern, '*', '%'), 'x', '%')
                ORDER BY specificity ASC
                """)
                .param("packageName", packageName)
                .param("version", version)
                .param("ecosystem", ecosystem)
                .query(MatchedPolicyDto.class)
                .list();
    }
}
