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

import com.silicaproxy.model.dto.PolicyEvaluationResponse;
import com.silicaproxy.model.dto.PolicySimulationRequest;
import com.silicaproxy.model.dto.SimulationPolicyInput;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PolicySimulationServiceTest {

    // simulate() never touches GitOpsDao (only evaluateFromDb does), so a null collaborator
    // is fine for these tests.
    private final PolicySimulationService service = new PolicySimulationService(null);

    @Test
    void shouldNotTreatLiteralXAsWildcardOutsideTrailingSegment() {
        PolicySimulationRequest request = new PolicySimulationRequest(
                "npm", "weird-pkg", "1.0.0-abz",
                List.of(new SimulationPolicyInput("weird-pkg", "1.0.0-xyz", "BLACKLIST", "test")));

        PolicyEvaluationResponse response = service.simulate(request);

        assertThat(response.decision()).isEqualTo("NO_MATCH");
        assertThat(response.matchingRules()).isEmpty();
    }

    @Test
    void shouldMatchExactLiteralVersionContainingX() {
        PolicySimulationRequest request = new PolicySimulationRequest(
                "npm", "weird-pkg", "1.0.0-xyz",
                List.of(new SimulationPolicyInput("weird-pkg", "1.0.0-xyz", "BLACKLIST", "test")));

        PolicyEvaluationResponse response = service.simulate(request);

        assertThat(response.decision()).isEqualTo("BLOCKED");
    }

    @Test
    void shouldTreatTrailingDotXSegmentAsWildcard() {
        PolicySimulationRequest request = new PolicySimulationRequest(
                "npm", "jquery", "1.2.9",
                List.of(new SimulationPolicyInput("jquery", "1.2.x", "BLACKLIST", "test")));

        PolicyEvaluationResponse response = service.simulate(request);

        assertThat(response.decision()).isEqualTo("BLOCKED");
    }

    @Test
    void shouldPreferBlacklistOverWhitelistAtEqualSpecificity() {
        // Two policies with identical package/version (same specificity), WHITELIST listed
        // first in the input : BLACKLIST must still win deterministically.
        PolicySimulationRequest request = new PolicySimulationRequest(
                "npm", "tie-break-pkg", "1.0.0",
                List.of(
                        new SimulationPolicyInput("tie-break-pkg", "1.0.0", "WHITELIST", "Approved"),
                        new SimulationPolicyInput("tie-break-pkg", "1.0.0", "BLACKLIST", "Actually compromised")));

        PolicyEvaluationResponse response = service.simulate(request);

        assertThat(response.decision()).isEqualTo("BLOCKED");
        assertThat(response.matchingRules().get(0).policyAction()).isEqualTo("BLACKLIST");
        assertThat(response.matchingRules().get(0).wins()).isTrue();
    }

    @Test
    void shouldTreatAsteriskAsWildcardAnywhere() {
        PolicySimulationRequest request = new PolicySimulationRequest(
                "npm", "shelljs", "9.9.9",
                List.of(new SimulationPolicyInput("shelljs", "*", "BLACKLIST", "test")));

        PolicyEvaluationResponse response = service.simulate(request);

        assertThat(response.decision()).isEqualTo("BLOCKED");
    }
}
