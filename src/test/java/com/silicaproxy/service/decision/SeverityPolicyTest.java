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


package com.silicaproxy.service.decision;

import com.silicaproxy.model.dto.AdvisoryFinding;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.SeverityThreshold;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SeverityPolicyTest {

    // max-allowed-severity: MEDIUM, max-allowed-cvss: 7.0 (pypi/maven defaults)
    private static final SeverityThreshold MEDIUM_7 = new SeverityThreshold(7.0, 7.0, true);

    private final SeverityPolicy policy = new SeverityPolicy(mock(com.silicaproxy.properties.SilicaProxyProperties.class),
            mock(SeverityMappingsCache.class));

    private static ApiCheckResult osvAnswer(AdvisoryFinding... findings) {
        return ApiCheckResult.ofFindings(200, 5, List.of(findings));
    }

    @Test
    void unscoredAdvisoryShouldBeJudgedOnItsScoredAlias() {
        ApiCheckResult result = policy.apply(osvAnswer(
                new AdvisoryFinding("PYSEC-2021-142", List.of("CVE-2020-14343", "GHSA-8q59-q68h-6hv4"), null),
                new AdvisoryFinding("GHSA-8q59-q68h-6hv4", List.of("CVE-2020-14343"), 9.8)), MEDIUM_7);

        assertThat(result.vulnerable()).isTrue();
        assertThat(result.vulnerabilityIds()).containsExactlyInAnyOrder("PYSEC-2021-142", "GHSA-8q59-q68h-6hv4");
    }

    @Test
    void unscoredAdvisoryWithModerateAliasShouldBeAllowed() {
        // Linked through the common CVE id only
        ApiCheckResult result = policy.apply(osvAnswer(
                new AdvisoryFinding("PYSEC-1", List.of("CVE-1"), null),
                new AdvisoryFinding("GHSA-1", List.of("CVE-1"), 4.0)), MEDIUM_7);

        assertThat(result.vulnerable()).isFalse();
        assertThat(result.vulnerabilityIds()).isEmpty();
        assertThat(result.vulnerabilitiesCount()).isEqualTo(2);
    }

    @Test
    void orphanAdvisoryShouldFollowUnknownSeverityAction() {
        ApiCheckResult orphan = osvAnswer(new AdvisoryFinding("PYSEC-9", List.of("CVE-9"), null));

        assertThat(policy.apply(orphan, MEDIUM_7).vulnerable()).isTrue();
        assertThat(policy.apply(orphan, new SeverityThreshold(7.0, 7.0, false)).vulnerable()).isFalse();
    }

    @Test
    void malwareShouldBlockWhateverTheThreshold() {
        ApiCheckResult result = policy.apply(osvAnswer(new AdvisoryFinding("MAL-2024-1", List.of(), null)),
                SeverityThreshold.disabled());

        assertThat(result.vulnerable()).isTrue();
        assertThat(result.vulnerabilityIds()).containsExactly("MAL-2024-1");
    }

    @Test
    void onlyBlockingGroupsShouldBeReported() {
        ApiCheckResult result = policy.apply(osvAnswer(
                new AdvisoryFinding("GHSA-low", List.of(), 3.1),
                new AdvisoryFinding("GHSA-high", List.of(), 7.5)), MEDIUM_7);

        assertThat(result.vulnerable()).isTrue();
        assertThat(result.vulnerabilityIds()).containsExactly("GHSA-high");
    }

    @Test
    void resultWithoutFindingsOrInErrorShouldBeKept() {
        ApiCheckResult legacy = new ApiCheckResult(true, 1, 200, 5, null);
        ApiCheckResult error = new ApiCheckResult(false, 0, 500, 5, "boom");

        assertThat(policy.apply(legacy, MEDIUM_7)).isSameAs(legacy);
        assertThat(policy.apply(error, MEDIUM_7)).isSameAs(error);
    }
}
