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
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Separate Spring context from {@link SecurityServiceTest} : the fail-open flag under test
 * is a startup-bound configuration property, so it can't be flipped per test method.
 * One fail-closed source among the attempted ones is enough to BLOCK when the whole
 * fallback chain errors (most restrictive wins) -- here OSV is fail-closed while deps.dev
 * keeps its fail-open default.
 */
// deps-dev.enabled is set explicitly (even though application.yaml already defaults it to
// true) : when only osv.fail-open is overridden here while BaseIntegrationTest's
// @DynamicPropertySource separately sets deps-dev.url, Spring's relaxed Map binding for
// apiFallback does not reliably merge deps-dev's other fields from application.yaml, and
// deps-dev.enabled silently resolves to its Java default (false) instead of true.
@TestPropertySource(properties = {
        "silicaproxy.api-fallback.osv.fail-open=false",
        "silicaproxy.api-fallback.deps-dev.enabled=true"
})
class SecurityServiceFallbackFailClosedTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceFallbackFailClosedTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDbAndWiremock() {
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    @Test
    void shouldFailClosedWithoutCachingWhenAllFallbackApisFail() {
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/fail-closed-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"fail-closed-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        // OSV down ; deps.dev has no stub, so WireMock answers 404 -- the whole chain errors.
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withStatus(500)));

        DecisionResult decision = securityService.getDecision("fail-closed-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("API_FALLBACK_ERROR");
        assertThat(decision.reason()).contains("fail-closed");

        // Error verdicts are never cached, fail-closed included : the block must lift by
        // itself on the next request once an API answers again.
        Integer cachedRows = jdbcClient.sql(
                "SELECT COUNT(*) FROM api_cache WHERE package_name = 'fail-closed-pkg'")
                .query(Integer.class).single();
        assertThat(cachedRows).isZero();
    }

    @Test
    void shouldStillConcludeNormallyWhenNextSourceAnswersDespiteFailClosedFirstSource() {
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/fail-closed-recover-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"fail-closed-recover-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        // OSV (fail-closed) errors, but deps.dev answers : its verdict concludes the chain,
        // so OSV's fail-closed policy never has to kick in.
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withStatus(500)));
        wireMock.stubFor(get(urlEqualTo("/depsdev/v3/systems/NPM/packages/fail-closed-recover-pkg/versions/1.0.0"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("fail-closed-recover-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("DEPS_DEV");
    }
}
