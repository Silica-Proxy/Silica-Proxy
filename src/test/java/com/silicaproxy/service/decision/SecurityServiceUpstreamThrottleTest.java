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
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.Verdict;
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
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * upstream-throttle.on-throttle=FAIL_CLOSED (the default), with fail-open everywhere else : a 429
 * from the registry or from OSV blocks (UPSTREAM_THROTTLED, never cached) instead of letting the
 * package through, while a plain outage keeps following fail-open.
 */
@TestPropertySource(properties = {
    "silicaproxy.quarantine.fail-open=true",
    "silicaproxy.quarantine.check-vulnerabilities-on-registry-error=true",
    "silicaproxy.api-fallback.osv.enabled=true",
    "silicaproxy.api-fallback.osv.fail-open=true",
    "silicaproxy.api-fallback.deps-dev.enabled=false",
    "silicaproxy.api-cache.cache-allow-verdict=true"
})
class SecurityServiceUpstreamThrottleTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceUpstreamThrottleTest(SecurityService securityService, JdbcClient jdbcClient) {
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

    private long apiCacheRows(String packageName) {
        return jdbcClient.sql("SELECT COUNT(*) FROM api_cache WHERE package_name = ?")
                .param(packageName).query(Long.class).single();
    }

    private static String packument(String version, Instant publishedAt) {
        return "{\"time\":{\"" + version + "\":\"" + publishedAt + "\"},"
                + "\"versions\":{\"" + version + "\":{\"version\":\"" + version + "\"}}}";
    }

    private void stubOsvClean() {
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(okJson("{}")));
    }

    @Test
    void shouldBlockWhenTheRegistryIsRateLimitingAndNoDateIsCached() {
        wireMock.stubFor(get(urlEqualTo("/throttled-pkg")).willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));
        stubOsvClean();

        DecisionResult decision = securityService.getDecision("throttled-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.UPSTREAM_THROTTLED);
        assertThat(apiCacheRows("throttled-pkg")).isZero();
        // Blocked before the vulnerability APIs : nothing to ask them without a publish date.
        wireMock.verify(0, postRequestedFor(urlEqualTo("/v1/query")));
    }

    @Test
    void shouldKeepBlockingWithoutCallingTheSuspendedRegistryThenDecideOnceItAnswers() {
        wireMock.stubFor(get(urlEqualTo("/recovering-pkg")).willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        assertThat(securityService.getDecision("recovering-pkg", "1.0.0", "npm", "").sourceType())
                .isEqualTo(DecisionSource.UPSTREAM_THROTTLED);
        assertThat(securityService.getDecision("recovering-pkg", "1.0.0", "npm", "").sourceType())
                .isEqualTo(DecisionSource.UPSTREAM_THROTTLED);
        wireMock.verify(1, getRequestedFor(urlEqualTo("/recovering-pkg")));
    }

    // Every upstream is the same WireMock host here, so OSV is suspended along with the registry :
    // the decision reaching the vulnerability APIs is what shows the cached date was used.
    @Test
    void shouldGoOnFromTheCachedDateWhenTheRegistryIsRateLimiting() {
        jdbcClient.sql("INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at) "
                        + "VALUES ('cached-throttled-pkg', 'npm', '1.0.0', :publishedAt)")
                .param("publishedAt", Timestamp.from(Instant.now().minus(100, ChronoUnit.DAYS)))
                .update();
        wireMock.stubFor(get(urlEqualTo("/cached-throttled-pkg")).willReturn(aResponse().withStatus(429)));
        stubOsvClean();

        DecisionResult decision = securityService.getDecision("cached-throttled-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.UPSTREAM_THROTTLED);
        assertThat(decision.reason()).contains("vulnerability APIs");
        wireMock.verify(0, postRequestedFor(urlEqualTo("/v1/query")));
    }

    @Test
    void shouldStillFollowFailOpenOnAPlainRegistryOutage() {
        wireMock.stubFor(get(urlEqualTo("/down-pkg")).willReturn(aResponse().withStatus(503)));
        stubOsvClean();

        DecisionResult decision = securityService.getDecision("down-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.REGISTRY_ERROR);
    }

    @Test
    void shouldBlockWhenOsvIsRateLimitingEvenWithOsvFailOpen() {
        wireMock.stubFor(get(urlEqualTo("/osv-throttled-pkg"))
                .willReturn(okJson(packument("1.0.0", Instant.now().minus(100, ChronoUnit.DAYS)))));
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        DecisionResult decision = securityService.getDecision("osv-throttled-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.UPSTREAM_THROTTLED);
        assertThat(apiCacheRows("osv-throttled-pkg")).isZero();
    }

    @Test
    void shouldStillFollowOsvFailOpenOnAPlainOsvOutage() {
        wireMock.stubFor(get(urlEqualTo("/osv-down-pkg"))
                .willReturn(okJson(packument("1.0.0", Instant.now().minus(100, ChronoUnit.DAYS)))));
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(aResponse().withStatus(503)));

        DecisionResult decision = securityService.getDecision("osv-down-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.API_FALLBACK_ERROR);
    }
}
