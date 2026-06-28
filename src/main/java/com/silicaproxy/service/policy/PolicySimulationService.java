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
 * an exact rule (specificity 0) always takes precedence over a generic pattern (specificity 1).
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
            if (!policy.packageName().equals(packageName)) {
                continue;
            }
            if (!versionMatchesPattern(version, policy.versionPattern())) {
                continue;
            }
            int specificity = policy.versionPattern().equals(version) ? 0 : 1;
            matches.add(new MatchedPolicyDto(
                    policy.packageName(),
                    policy.versionPattern(),
                    policy.policyAction(),
                    policy.reason(),
                    specificity,
                    false));
        }
        matches.sort(Comparator.comparingInt(MatchedPolicyDto::specificity));
        return matches;
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

    // Reproduces SQL logic : REPLACE(REPLACE(version_pattern, '*', '%'), 'x', '%')
    // then checks if the version matches the SQL LIKE pattern.
    private boolean versionMatchesPattern(String version, String pattern) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '*' || c == 'x') {
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
