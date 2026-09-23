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

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.DecisionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A wheel uploaded yesterday to a release first published two years ago must be quarantined :
 * the age is the one of the downloaded file, not of the release's first file.
 */
@TestPropertySource(properties = {
    "silicaproxy.api-fallback.osv.enabled=false",
    "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServicePypiFileDateQuarantineTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServicePypiFileDateQuarantineTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
        String oldUpload = Instant.now().minus(730, ChronoUnit.DAYS).toString();
        String freshUpload = Instant.now().minus(1, ChronoUnit.DAYS).toString();
        wireMock.stubFor(get(urlEqualTo("/pypi/late-wheel-pkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"releases\": {\"1.0.0\": ["
                                + "{\"filename\": \"late_wheel_pkg-1.0.0.tar.gz\", \"upload_time_iso_8601\": \"" + oldUpload + "\"},"
                                + "{\"filename\": \"late_wheel_pkg-1.0.0-py3-none-any.whl\", \"upload_time_iso_8601\": \"" + freshUpload + "\"}"
                                + "]}}")));
    }

    @Test
    void shouldQuarantineAFreshWheelAddedToAnOldRelease() {
        String fullUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0-py3-none-any.whl";

        DecisionResult decision = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", fullUrl);

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_QUARANTINE");
    }

    @Test
    void shouldAllowTheOldSdistOfTheSameRelease() {
        String fullUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0.tar.gz";

        DecisionResult decision = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", fullUrl);

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_QUARANTINE");
    }
}
