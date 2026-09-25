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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With {@code quarantine.check-vulnerabilities-on-registry-error=true}, a package let through by
 * fail-open (publish date unresolved) still goes through the live vulnerability APIs : a BLOCK
 * wins, and an ALLOW is never written to api_cache (it would short-circuit the quarantine check
 * once the registry recovers).
 */
@TestPropertySource(properties = {
    "silicaproxy.quarantine.check-vulnerabilities-on-registry-error=true",
    "silicaproxy.api-fallback.osv.enabled=true",
    "silicaproxy.api-fallback.deps-dev.enabled=false",
    "silicaproxy.api-cache.cache-allow-verdict=true"
})
class SecurityServiceRegistryErrorVulnCheckTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceRegistryErrorVulnCheckTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDbAndWiremock() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    private long allowRowsInApiCache(String packageName) {
        return jdbcClient.sql("SELECT COUNT(*) FROM api_cache WHERE package_name = ? AND is_secure")
                .param(packageName).query(Long.class).single();
    }

    @Test
    void shouldBlockWhenRegistryIsDownAndOsvReportsVulnerability() {
        wireMock.stubFor(get(urlEqualTo("/vuln-during-outage")).willReturn(aResponse().withStatus(503)));
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"vulns\": [{\"id\": \"CVE-2024-001\"}]}")));

        DecisionResult decision = securityService.getDecision("vuln-during-outage", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldAllowWithoutCachingWhenRegistryIsDownAndOsvIsClean() {
        wireMock.stubFor(get(urlEqualTo("/clean-during-outage")).willReturn(aResponse().withStatus(503)));
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{}")));

        DecisionResult decision = securityService.getDecision("clean-during-outage", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(allowRowsInApiCache("clean-during-outage")).isZero();
    }

    @Test
    void shouldStayFailOpenWhenRegistryAndOsvAreBothDown() {
        wireMock.stubFor(get(urlEqualTo("/all-down-pkg")).willReturn(aResponse().withStatus(503)));
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(aResponse().withStatus(503)));

        DecisionResult decision = securityService.getDecision("all-down-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(allowRowsInApiCache("all-down-pkg")).isZero();
    }
}
