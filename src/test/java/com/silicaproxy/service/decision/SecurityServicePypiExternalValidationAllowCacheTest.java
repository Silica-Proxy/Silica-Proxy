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
import com.silicaproxy.model.dto.Verdict;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * An ALLOW vetted by the external validation services is cached for the whole version : it
 * must not be while another file of the PyPI release is still quarantined, otherwise that file
 * would be served off the cached ALLOW without the quarantine check.
 */
class SecurityServicePypiExternalValidationAllowCacheTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServicePypiExternalValidationAllowCacheTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url",
                () -> "http://localhost:" + wireMock.port() + "/external-validate");
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.test-scanner.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "true");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(okJson("{\"verdict\":\"ALLOWED\",\"reason\":\"Clean\"}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(okJson("{}")));
    }

    @Test
    void shouldNotCacheTheVettedAllowOfAnOldFileWhileAFreshFileOfTheReleaseIsQuarantined() {
        stubRelease("late-wheel-ext-pkg", Instant.now().minus(1, ChronoUnit.DAYS));

        DecisionResult sdist = securityService.getDecision("late-wheel-ext-pkg", "1.0.0", "pypi",
                "https://files.pythonhosted.org/packages/ab/cd/late_wheel_ext_pkg-1.0.0.tar.gz");

        assertThat(sdist.result()).isEqualTo(Verdict.ALLOW);
        assertThat(apiCacheRows("late-wheel-ext-pkg")).isZero();
    }

    @Test
    void shouldCacheTheVettedAllowOnceEveryFileOfTheReleaseIsPastQuarantine() {
        stubRelease("old-release-ext-pkg", Instant.now().minus(700, ChronoUnit.DAYS));

        DecisionResult sdist = securityService.getDecision("old-release-ext-pkg", "1.0.0", "pypi",
                "https://files.pythonhosted.org/packages/ab/cd/old_release_ext_pkg-1.0.0.tar.gz");

        assertThat(sdist.result()).isEqualTo(Verdict.ALLOW);
        assertThat(apiCacheRows("old-release-ext-pkg")).isEqualTo(1);
    }

    // An old sdist plus a wheel uploaded at wheelUpload.
    private void stubRelease(String packageName, Instant wheelUpload) {
        String fileStem = packageName.replace('-', '_') + "-1.0.0";
        String sdistUpload = Instant.now().minus(730, ChronoUnit.DAYS).toString();
        wireMock.stubFor(get(urlEqualTo("/pypi/" + packageName + "/json"))
                .willReturn(okJson("{\"releases\": {\"1.0.0\": ["
                        + "{\"filename\": \"" + fileStem + ".tar.gz\", \"upload_time_iso_8601\": \"" + sdistUpload + "\"},"
                        + "{\"filename\": \"" + fileStem + "-py3-none-any.whl\", \"upload_time_iso_8601\": \"" + wheelUpload + "\"}"
                        + "]}}")));
    }

    private long apiCacheRows(String packageName) {
        return jdbcClient.sql("SELECT COUNT(*) FROM api_cache WHERE package_name = :name")
                .param("name", packageName)
                .query(Long.class).single();
    }
}
