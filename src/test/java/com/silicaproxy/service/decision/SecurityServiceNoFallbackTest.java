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

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

@TestPropertySource(properties = {
    "silicaproxy.api-fallback.osv.enabled=false",
    "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServiceNoFallbackTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceNoFallbackTest(SecurityService securityService, JdbcClient jdbcClient) {
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
    }

    @Test
    void shouldAllowByDefaultWhenNoFallbackEnabled() {
        // No vulnerability, no policy, no fallback API enabled.
        // SecurityService must return DEFAULT/ALLOW and write a record
        // in api_cache with is_secure=true and TTL 24h (spec §4.3 step 4,
        // SecurityService L155-157).
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/no-fallback-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"no-fallback-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        DecisionResult decision = securityService.getDecision("no-fallback-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("DEFAULT");
        assertThat(decision.reason()).contains("default");

        Map<String, Object> cache = jdbcClient.sql(
                "SELECT * FROM api_cache WHERE package_name = 'no-fallback-pkg'").query().singleRow();
        assertThat(cache.get("is_secure")).isEqualTo(true);
        assertThat(cache.get("api_source")).isEqualTo("DEFAULT");
        Instant expiresAt = ((Timestamp) cache.get("expires_at")).toInstant();
        assertThat(expiresAt).isAfter(Instant.now().plus(23, ChronoUnit.HOURS));
        assertThat(expiresAt).isBefore(Instant.now().plus(25, ChronoUnit.HOURS));
    }
}
