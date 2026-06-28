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


package com.silicaproxy.config;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.decision.SecurityService;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

// Tests that corporate-proxy.scope.registries correctly controls whether registry calls
// transit through the corporate proxy. Uses an unreachable proxy (127.0.0.1:1) as a sentinel:
// if scope is active, calls fail with REGISTRY_ERROR; if disabled, they reach WireMock directly.
//
// Both git scopes are disabled explicitly: GitProxyConfig sets HttpTransport.setConnectionFactory()
// as JVM-wide static state, and Spring's test context cache keeps contexts alive without calling
// @PreDestroy between test classes. Keeping externalGitRepositories=false ensures the leaked
// factory returns Proxy.NO_PROXY for any git host, preventing interference with subsequent
// Gitea-based tests regardless of which hostname Testcontainers assigns (localhost vs docker).
@NullMarked
class CorporateProxyScopeRegistriesTest {

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
            "silicaproxy.corporate-proxy.enabled=true",
            "silicaproxy.corporate-proxy.host=127.0.0.1",
            "silicaproxy.corporate-proxy.port=1",
            "silicaproxy.corporate-proxy.non-proxy-hosts=none-matches-anything.invalid",
            "silicaproxy.corporate-proxy.scope.registries=false",
            "silicaproxy.corporate-proxy.scope.security-apis=false",
            "silicaproxy.corporate-proxy.scope.external-git-repositories=false",
            "silicaproxy.corporate-proxy.scope.internal-git-repository=false",
            "silicaproxy.gitops.repository-url=http://localhost:3000/devops/policies.git"
    })
    class WhenRegistriesScopeIsDisabled extends BaseIntegrationTest {

        private final SecurityService securityService;
        private final JdbcClient jdbcClient;

        @Autowired
        WhenRegistriesScopeIsDisabled(SecurityService securityService, JdbcClient jdbcClient) {
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

        @Test
        void shouldBypassUnreachableProxyWhenRegistriesScopeIsDisabled() {
            Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
            wireMock.stubFor(get(urlEqualTo("/scope-disabled-pkg"))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"time\": {\"1.0.0\": \"" + publishedAt
                                    + "\"}, \"versions\": {\"1.0.0\": {}}}")));
            wireMock.stubFor(post(urlEqualTo("/v1/query"))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json")
                            .withBody("{}")));

            DecisionResult decision = securityService.getDecision("scope-disabled-pkg", "1.0.0", "npm");

            assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
            "silicaproxy.corporate-proxy.enabled=true",
            "silicaproxy.corporate-proxy.host=127.0.0.1",
            "silicaproxy.corporate-proxy.port=1",
            "silicaproxy.corporate-proxy.non-proxy-hosts=none-matches-anything.invalid",
            "silicaproxy.corporate-proxy.scope.registries=true",
            "silicaproxy.corporate-proxy.scope.security-apis=false",
            "silicaproxy.corporate-proxy.scope.external-git-repositories=false",
            "silicaproxy.corporate-proxy.scope.internal-git-repository=false",
            "silicaproxy.gitops.repository-url=http://localhost:3000/devops/policies.git"
    })
    class WhenRegistriesScopeIsEnabled extends BaseIntegrationTest {

        private final SecurityService securityService;
        private final JdbcClient jdbcClient;

        @Autowired
        WhenRegistriesScopeIsEnabled(SecurityService securityService, JdbcClient jdbcClient) {
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

        @Test
        void shouldRouteThroughUnreachableProxyWhenRegistriesScopeIsEnabled() {
            wireMock.stubFor(get(urlEqualTo("/scope-enabled-pkg"))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"time\": {\"1.0.0\": \"2020-01-01T00:00:00Z\"},"
                                    + " \"versions\": {\"1.0.0\": {}}}")));

            DecisionResult decision = securityService.getDecision("scope-enabled-pkg", "1.0.0", "npm");

            assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
            assertThat(decision.result()).isEqualTo("ALLOW");
        }
    }
}
