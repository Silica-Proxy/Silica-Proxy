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
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With {@code quarantine.unknown-version-action=BLOCK}, a version every registry answered it does
 * not know is blocked ({@code REGISTRY_NOT_FOUND}), while a registry that could not answer still
 * follows the fail-open policy (true in the test profile).
 */
@TestPropertySource(properties = {
    "silicaproxy.quarantine.unknown-version-action=BLOCK",
    "silicaproxy.api-fallback.osv.enabled=false",
    "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServiceUnknownVersionActionTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceUnknownVersionActionTest(SecurityService securityService, JdbcClient jdbcClient) {
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

    @Test
    void shouldBlockPypiPackageUnknownToRegistry() {
        wireMock.stubFor(get(urlEqualTo("/pypi/ghost-pkg/json")).willReturn(aResponse().withStatus(404)));

        DecisionResult decision = securityService.getDecision("ghost-pkg", "1.0.0", "pypi", "");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_NOT_FOUND");
    }

    @Test
    void shouldBlockPypiVersionAbsentFromReleases() {
        wireMock.stubFor(get(urlEqualTo("/pypi/known-pkg/json")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"releases\":{\"1.0.0\":[{\"filename\":\"known_pkg-1.0.0.tar.gz\","
                        + "\"upload_time_iso_8601\":\"2020-01-01T00:00:00Z\"}]}}")));

        DecisionResult decision = securityService.getDecision("known-pkg", "9.9.9", "pypi", "");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_NOT_FOUND");
    }

    @Test
    void shouldFollowFailOpenWhenPypiIsDown() {
        wireMock.stubFor(get(urlEqualTo("/pypi/down-pkg/json")).willReturn(aResponse().withStatus(500)));

        DecisionResult decision = securityService.getDecision("down-pkg", "1.0.0", "pypi", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldBlockMavenArtifactUnknownToCentralAndInterceptedUrl() {
        wireMock.stubFor(head(urlEqualTo("/maven2/com/example/ghost/1.0.0/")).willReturn(aResponse().withStatus(404)));
        String interceptedPath = "/repository/maven-proxy/com/example/ghost/1.0.0/ghost-1.0.0.jar";
        wireMock.stubFor(head(urlEqualTo(interceptedPath)).willReturn(aResponse().withStatus(404)));

        DecisionResult decision = securityService.getDecision(
                "com.example:ghost", "1.0.0", "maven", wireMock.baseUrl() + interceptedPath);

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_NOT_FOUND");
    }

    @Test
    void shouldFollowFailOpenWhenMavenCentralIsDown() {
        wireMock.stubFor(head(urlEqualTo("/maven2/com/example/down/1.0.0/")).willReturn(aResponse().withStatus(503)));

        DecisionResult decision = securityService.getDecision("com.example:down", "1.0.0", "maven", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldBlockNpmPackageUnknownToPublicRegistryWithoutOrigin() {
        wireMock.stubFor(get(urlEqualTo("/ghost-npm-pkg")).willReturn(aResponse().withStatus(404)));

        DecisionResult decision = securityService.getDecision("ghost-npm-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_NOT_FOUND");
    }

    @Test
    void shouldFollowFailOpenWhenNpmRegistryIsDown() {
        wireMock.stubFor(get(urlEqualTo("/down-npm-pkg")).willReturn(aResponse().withStatus(503)));

        DecisionResult decision = securityService.getDecision("down-npm-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldNeverCacheUnknownVersionVerdict() {
        wireMock.stubFor(get(urlEqualTo("/pypi/later-pkg/json")).willReturn(aResponse().withStatus(404)));
        securityService.getDecision("later-pkg", "1.0.0", "pypi", "");
        assertThat(apiCacheRows("later-pkg")).isZero();

        // The version shows up on the registry : the next request is evaluated afresh.
        wireMock.resetAll();
        wireMock.stubFor(get(urlEqualTo("/pypi/later-pkg/json")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"releases\":{\"1.0.0\":[{\"filename\":\"later_pkg-1.0.0.tar.gz\","
                        + "\"upload_time_iso_8601\":\"2020-01-01T00:00:00Z\"}]}}")));

        DecisionResult decision = securityService.getDecision("later-pkg", "1.0.0", "pypi", "");

        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_NOT_FOUND");
        assertThat(decision.result()).isEqualTo("ALLOW");
    }
}
