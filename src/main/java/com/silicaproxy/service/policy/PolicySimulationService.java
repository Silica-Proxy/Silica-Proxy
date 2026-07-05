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


package com.silicaproxy.service.policy;

import com.silicaproxy.dao.policy.GitOpsDao;
import com.silicaproxy.model.dto.MatchedPolicyDto;
import com.silicaproxy.model.dto.PolicyEvaluationResponse;
import com.silicaproxy.model.dto.PolicySimulationRequest;
import com.silicaproxy.model.dto.SimulationPolicyInput;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Evaluates conflict resolution between {@code company_policies} rules for a package/version.
 * Two modes : database query via {@code GitOpsDao} ({@code evaluateFromDb}), or
 * pure in-memory simulation with rules provided as parameters ({@code simulate}).
 * The resolution logic faithfully reproduces that of the SQL in {@code DecisionDao} :
 * an exact package name always takes precedence over a wildcard package pattern, and
 * (as a tie-breaker within the same package specificity) an exact version always takes
 * precedence over a wildcard version pattern.
 */
@Service
@NullMarked
public class PolicySimulationService {

    private final GitOpsDao gitOpsDao;

    public PolicySimulationService(GitOpsDao gitOpsDao) {
        this.gitOpsDao = gitOpsDao;
    }

    public PolicyEvaluationResponse evaluateFromDb(String packageName, String version, String ecosystem) {
        List<MatchedPolicyDto> matches = gitOpsDao.findMatchingPolicies(packageName, version, ecosystem);
        return buildResponse(matches);
    }

    public PolicyEvaluationResponse simulate(PolicySimulationRequest request) {
        List<MatchedPolicyDto> matches = applyInMemory(
                request.packageName(), request.version(), request.policies());
        return buildResponse(matches);
    }

    private List<MatchedPolicyDto> applyInMemory(
            String packageName, String version, List<SimulationPolicyInput> policies) {

        List<MatchedPolicyDto> matches = new ArrayList<>();
        for (SimulationPolicyInput policy : policies) {
            if (!packageMatchesPattern(packageName, policy.packageName())) {
                continue;
            }
            if (!versionMatchesPattern(version, policy.versionPattern())) {
                continue;
            }
            int packageSpecificity = policy.packageName().equals(packageName) ? 0 : 2;
            int versionSpecificity = policy.versionPattern().equals(version) ? 0 : 1;
            matches.add(new MatchedPolicyDto(
                    policy.packageName(),
                    policy.versionPattern(),
                    policy.policyAction(),
                    policy.reason(),
                    packageSpecificity + versionSpecificity,
                    false));
        }
        // Tie-break at equal specificity : BLACKLIST wins over WHITELIST, rather than relying
        // on the input list's order (same rule as GitOpsDao.findMatchingPolicies / DecisionDao).
        matches.sort(Comparator
                .comparingInt(MatchedPolicyDto::specificity)
                .thenComparing(m -> "BLACKLIST".equals(m.policyAction()) ? 0 : 1));
        return matches;
    }

    // Reproduces SQL logic : REPLACE(package_name, '*', '%'). Unlike versions, 'x' is NOT
    // treated as a wildcard here : real package names commonly contain the literal letter 'x'
    // (axios, next, xml2js, regexp...), so doing so would cause unintended broad matches.
    private boolean packageMatchesPattern(String packageName, String pattern) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '*') {
                regex.append(".*");
            } else if (c == '.') {
                regex.append("\\.");
            } else if ("\\+?()[]{}^$|".indexOf(c) >= 0) {
                regex.append('\\').append(c);
            } else {
                regex.append(c);
            }
        }
        regex.append("$");
        return packageName.matches(regex.toString());
    }

    private PolicyEvaluationResponse buildResponse(List<MatchedPolicyDto> matches) {
        if (matches.isEmpty()) {
            return new PolicyEvaluationResponse("NO_MATCH", List.of());
        }

        MatchedPolicyDto winner = matches.get(0);
        String decision = "WHITELIST".equals(winner.policyAction()) ? "ALLOWED" : "BLOCKED";

        List<MatchedPolicyDto> withWins = new ArrayList<>(matches.size());
        for (int i = 0; i < matches.size(); i++) {
            MatchedPolicyDto m = matches.get(i);
            withWins.add(new MatchedPolicyDto(
                    m.packageName(), m.versionPattern(), m.policyAction(),
                    m.reason(), m.specificity(), i == 0));
        }

        return new PolicyEvaluationResponse(decision, withWins);
    }

    // Reproduces GitOpsSyncService.toSqlWildcardPattern's semantics for a raw, untranslated
    // pattern supplied directly in a simulation request (simulate() patterns are not pre-
    // translated the way company_policies.version_pattern is at GitOps write time) : 'x'/'X' is
    // only a wildcard as a full trailing version *segment* (e.g. "1.2.x"), never as a literal
    // character occurring elsewhere (e.g. "1.0.0-xyz" must stay literal). '*' is always a
    // wildcard.
    private boolean versionMatchesPattern(String version, String pattern) {
        StringBuilder regex = new StringBuilder("^");
        int length = pattern.length();
        for (int i = 0; i < length; i++) {
            char c = pattern.charAt(i);
            boolean isTrailingWildcardSegment = (c == 'x' || c == 'X') && i == length - 1 && i > 0 && pattern.charAt(i - 1) == '.';
            if (c == '*' || isTrailingWildcardSegment) {
                regex.append(".*");
            } else if (c == '.') {
                regex.append("\\.");
            } else if ("\\+?()[]{}^$|".indexOf(c) >= 0) {
                regex.append('\\').append(c);
            } else {
                regex.append(c);
            }
        }
        regex.append("$");
        return version.matches(regex.toString());
    }
}
