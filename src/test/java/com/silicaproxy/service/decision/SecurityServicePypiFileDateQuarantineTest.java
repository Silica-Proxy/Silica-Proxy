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

import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.Verdict;
import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.DecisionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
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

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.REGISTRY_QUARANTINE);
    }

    @Test
    void shouldAllowTheOldSdistOfTheSameRelease() {
        String fullUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0.tar.gz";

        DecisionResult decision = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", fullUrl);

        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.sourceType()).isNotEqualTo(DecisionSource.REGISTRY_QUARANTINE);
    }

    @Test
    void shouldQuarantineAFreshWheelEvenAfterTheOldSdistOfTheSameReleaseWasAllowed() {
        String sdistUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0.tar.gz";
        String wheelUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0-py3-none-any.whl";

        DecisionResult sdist = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", sdistUrl);
        DecisionResult wheel = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", wheelUrl);

        assertThat(sdist.result()).isEqualTo(Verdict.ALLOW);
        assertThat(wheel.result()).isEqualTo(Verdict.BLOCK);
        assertThat(wheel.sourceType()).isEqualTo(DecisionSource.REGISTRY_QUARANTINE);
    }

    @Test
    void shouldQuarantineOffAStillQuarantinedCachedPublishDateWithoutCallingPypi() {
        // The release holds a fresh file : blocked without a lookup, even for its old sdist
        // (the accepted false positive, until the fresh file leaves quarantine). With no lookup,
        // a PyPI error ("too many concurrent streams" under load) can't hand it to fail-open.
        cachePublishedAt("late-wheel-pkg", Instant.now().minus(1, ChronoUnit.DAYS));
        String sdistUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0.tar.gz";

        DecisionResult decision = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", sdistUrl);

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.REGISTRY_QUARANTINE);
        wireMock.verify(0, getRequestedFor(urlEqualTo("/pypi/late-wheel-pkg/json")));
    }

    @Test
    void shouldAskPypiWhenTheCachedPublishDateIsPastQuarantine() {
        // The cached date was the old sdist's : it says nothing about the fresh wheel requested now.
        cachePublishedAt("late-wheel-pkg", Instant.now().minus(730, ChronoUnit.DAYS));
        String wheelUrl = "https://files.pythonhosted.org/packages/ab/cd/late_wheel_pkg-1.0.0-py3-none-any.whl";

        DecisionResult decision = securityService.getDecision("late-wheel-pkg", "1.0.0", "pypi", wheelUrl);

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.REGISTRY_QUARANTINE);
        wireMock.verify(1, getRequestedFor(urlEqualTo("/pypi/late-wheel-pkg/json")));
    }

    @Test
    void shouldNotDateAFileOffTheCachedPublishDateWhilePypiIsDown() {
        // The cached date was the old sdist's : standing in for a fresh wheel during the outage,
        // it would pass the quarantine check and cache an ALLOW for the whole release.
        cachePublishedAt("pypi-down-pkg", Instant.now().minus(730, ChronoUnit.DAYS));
        wireMock.stubFor(get(urlEqualTo("/pypi/pypi-down-pkg/json")).willReturn(aResponse().withStatus(500)));
        String wheelUrl = "https://files.pythonhosted.org/packages/ab/cd/pypi_down_pkg-1.0.0-py3-none-any.whl";

        DecisionResult decision = securityService.getDecision("pypi-down-pkg", "1.0.0", "pypi", wheelUrl);

        // fail-open in the test profile : allowed, but never cached
        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
        assertThat(jdbcClient.sql("SELECT COUNT(*) FROM api_cache WHERE package_name = 'pypi-down-pkg'")
                .query(Long.class).single()).isZero();
    }

    private void cachePublishedAt(String packageName, Instant publishedAt) {
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES (?, 'pypi', '1.0.0', ?)
                """).params(packageName, Timestamp.from(publishedAt)).update();
    }
}
