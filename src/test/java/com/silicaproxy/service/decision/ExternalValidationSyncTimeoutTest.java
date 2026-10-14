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
import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

// The SYNC wait is bounded by each service's own timeout-seconds, not by the global
// http-client.external-validation-read-timeout-seconds (which only covers ASYNC triggers).
// The two services below answer in 2 seconds while the global read timeout is 1 second.
class ExternalValidationSyncTimeoutTest extends BaseIntegrationTest {

    private static final String SLOW_SERVICE = "slow-scanner";
    private static final String FAST_SERVICE = "fast-scanner";

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private SecurityService securityService;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        registerService(registry, SLOW_SERVICE, "3");
        registerService(registry, FAST_SERVICE, "1");
        registry.add("silicaproxy.http-client.external-validation-read-timeout-seconds", () -> "1");
        registry.add("silicaproxy.quarantine.enabled", () -> "false");
        registry.add("silicaproxy.deprecation.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
    }

    private static void registerService(DynamicPropertyRegistry registry, String name, String timeoutSeconds) {
        String prefix = "silicaproxy.external-validation.services." + name + ".";
        registry.add(prefix + "enabled", () -> "true");
        registry.add(prefix + "url", () -> "http://localhost:" + wireMock.port() + "/" + name);
        registry.add(prefix + "mode", () -> Metrics.TYPE_SYNC);
        registry.add(prefix + "timeout-seconds", () -> timeoutSeconds);
        registry.add(prefix + "fail-open", () -> "true");
        registry.add(prefix + "blocking", () -> "true");
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES ('lodash', 'npm', '4.17.21', NOW() - INTERVAL '365 days')
                """).update();
        wireMock.resetAll();
    }

    @Test
    void sync_eachServiceWaitsForItsOwnTimeout() {
        for (String service : new String[] {SLOW_SERVICE, FAST_SERVICE}) {
            wireMock.stubFor(post(urlEqualTo("/" + service))
                    .willReturn(okJson("{\"verdict\":\"ALLOWED\",\"reason\":\"Clean\"}")
                            .withFixedDelay(2000)));
        }

        securityService.getDecision("lodash", "4.17.21", "npm", "");

        // timeout-seconds=3 > 2s answer : the verdict is received despite the 1s global timeout
        assertThat(cacheStatus(SLOW_SERVICE)).contains(Metrics.ALLOWED);
        // timeout-seconds=1 < 2s answer : the call times out
        assertThat(cacheStatus(FAST_SERVICE)).contains("TIMEOUT");
    }

    private Optional<String> cacheStatus(String service) {
        return cacheDao.findByServiceAndPackage(service, "lodash", "npm", "4.17.21")
                .map(ExternalValidationCacheEntry::status);
    }
}
