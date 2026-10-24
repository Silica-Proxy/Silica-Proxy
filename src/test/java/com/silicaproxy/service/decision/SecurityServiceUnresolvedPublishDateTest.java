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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A publish date that cannot be resolved only skips the quarantine check : with the default
 * configuration (fail-open, check-vulnerabilities-on-registry-error left at its default), the
 * external validation services and then the live vulnerability APIs still run, a BLOCK from
 * either wins, and the resulting ALLOW is never written to api_cache.
 */
class SecurityServiceUnresolvedPublishDateTest extends BaseIntegrationTest {

    private static final String SCANNER_PATH = "/external-validate";

    private final SecurityService securityService;
    private final JdbcClient jdbcClient;

    @Autowired
    SecurityServiceUnresolvedPublishDateTest(SecurityService securityService, JdbcClient jdbcClient) {
        this.securityService = securityService;
        this.jdbcClient = jdbcClient;
    }

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + SCANNER_PATH;
        registry.add("silicaproxy.external-validation.services.test-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.url", () -> extUrl);
        registry.add("silicaproxy.external-validation.services.test-scanner.mode", () -> "sync");
        registry.add("silicaproxy.external-validation.services.test-scanner.timeout-seconds", () -> "1");
        registry.add("silicaproxy.external-validation.services.test-scanner.fail-open", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.blocking", () -> "true");
        registry.add("silicaproxy.external-validation.services.test-scanner.cache-ttl-minutes", () -> "60");
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "true");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
        registry.add("silicaproxy.api-cache.cache-allow-verdict", () -> "true");
    }

    @BeforeEach
    void cleanDbAndWiremock() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    private static void stubRegistryDown(String packageName) {
        wireMock.stubFor(get(urlEqualTo("/" + packageName)).willReturn(aResponse().withStatus(503)));
    }

    private static void stubScanner(String verdict) {
        wireMock.stubFor(post(urlEqualTo(SCANNER_PATH))
                .willReturn(okJson("{\"verdict\":\"" + verdict + "\"}")));
    }

    private static void stubOsv(String body) {
        wireMock.stubFor(post(urlEqualTo("/v1/query")).willReturn(okJson(body)));
    }

    private static int scannerCalls() {
        return wireMock.findAll(postRequestedFor(urlEqualTo(SCANNER_PATH))).size();
    }

    private long apiCacheRows(String packageName) {
        return jdbcClient.sql("SELECT COUNT(*) FROM api_cache WHERE package_name = ?")
                .param(packageName).query(Long.class).single();
    }

    @Test
    void shouldEnforcePermanentBlockedVerdictWhenRegistryIsDown() {
        stubRegistryDown("blocked-during-outage");
        stubOsv("{}");
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts (service_name, package_name, ecosystem, package_version, reason)
                VALUES ('test-scanner', 'blocked-during-outage', 'npm', '1.0.0', 'malware')
                """).update();

        DecisionResult decision = securityService.getDecision("blocked-during-outage", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.EXTERNAL_VALIDATION);
        assertThat(scannerCalls()).isZero();
    }

    @Test
    void shouldBlockOnScannerVerdictWhenRegistryIsDown() {
        stubRegistryDown("scanner-blocks-during-outage");
        stubScanner("BLOCKED");
        stubOsv("{}");

        DecisionResult decision = securityService.getDecision("scanner-blocks-during-outage", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.EXTERNAL_VALIDATION);
    }

    @Test
    void shouldBlockOnOsvVulnerabilityWhenRegistryIsDownByDefault() {
        stubRegistryDown("vuln-during-outage");
        stubScanner("ALLOWED");
        stubOsv("{\"vulns\": [{\"id\": \"CVE-2024-001\"}]}");

        DecisionResult decision = securityService.getDecision("vuln-during-outage", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.OSV_LIVE);
        assertThat(scannerCalls()).isEqualTo(1);
    }

    @Test
    void shouldAllowWithoutCachingWhenRegistryIsDownAndEveryCheckIsClean() {
        stubRegistryDown("clean-during-outage");
        stubScanner("ALLOWED");
        stubOsv("{}");

        DecisionResult decision = securityService.getDecision("clean-during-outage", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.ALLOW);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.REGISTRY_ERROR);
        assertThat(scannerCalls()).isEqualTo(1);
        assertThat(apiCacheRows("clean-during-outage")).isZero();
    }

    // A package absent from the public registry (internal package served by a mirror) follows
    // fail-open under FOLLOW_FAIL_OPEN : it must still go through the external services.
    @Test
    void shouldRunExternalValidationForVersionUnknownToRegistry() {
        wireMock.stubFor(get(urlEqualTo("/internal-only-pkg")).willReturn(aResponse().withStatus(404)));
        stubScanner("BLOCKED");
        stubOsv("{}");

        DecisionResult decision = securityService.getDecision("internal-only-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.sourceType()).isEqualTo(DecisionSource.EXTERNAL_VALIDATION);
        assertThat(scannerCalls()).isEqualTo(1);
    }
}
