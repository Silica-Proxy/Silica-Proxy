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


package com.silicaproxy.controller;

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyControllerTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();
    private final JdbcClient jdbcClient;

    @Autowired
    PolicyControllerTest(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
    }

    // -------------------------------------------------------------------------
    // GET /api/policies/evaluate
    // -------------------------------------------------------------------------

    @Test
    void evaluateShouldReturnAllowedWhenWhitelistPolicyMatches() {
        // version_pattern is always pre-translated by GitOpsSyncService at write time ('*' is
        // stored as '%') -- this test inserts that translated form directly.
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '%', 'WHITELIST', 'Approved', 'admin')
                """).update();

        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"ALLOWED\"");
        assertThat(response.getBody()).contains("\"WHITELIST\"");
        assertThat(response.getBody()).contains("\"wins\":true");
    }

    @Test
    void evaluateShouldReturnBlockedWhenBlacklistPolicyMatches() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '%', 'BLACKLIST', 'Forbidden', 'admin')
                """).update();

        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"BLOCKED\"");
        assertThat(response.getBody()).contains("\"wins\":true");
    }

    @Test
    void evaluateShouldReturnNoMatchWhenNoPolicyMatches() {
        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=unknown-package&version=1.0.0");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"NO_MATCH\"");
        assertThat(response.getBody()).contains("\"matchingRules\":[]");
    }

    @Test
    void evaluateShouldShowConflictResolutionExactVersionBeatsWildcard() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '%', 'BLACKLIST', 'Forbidden by default', 'admin')
                """).update();
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '4.17.21', 'WHITELIST', 'Explicitly approved version', 'admin')
                """).update();

        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"ALLOWED\"");
        // Both rules returned, only one wins
        assertThat(response.getBody()).contains("\"wins\":true");
        assertThat(response.getBody()).contains("\"wins\":false");
    }

    @Test
    void evaluateShouldMatchPrefixWildcardPattern() {
        // version_pattern is always pre-translated by GitOpsSyncService at write time (a GitOps
        // rule version of '4.x' is stored here already as '4.%') -- this test inserts that
        // translated form directly to simulate the real write path.
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '4.%', 'WHITELIST', 'Series 4 approved', 'admin')
                """).update();

        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"ALLOWED\"");
    }

    @Test
    void evaluateShouldNotMatchOtherEcosystem() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'maven', '%', 'BLACKLIST', 'Other ecosystem', 'admin')
                """).update();

        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"NO_MATCH\"");
    }

    @Test
    void evaluateShouldReturn400WhenVersionMissing() {
        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&packageName=lodash");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void evaluateShouldReturn400WhenPackageNameMissing() {
        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?ecosystem=npm&version=1.0.0");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void evaluateShouldReturn400WhenEcosystemMissing() {
        ResponseEntity<String> response = getResponse(
                "/api/policies/evaluate?packageName=lodash&version=1.0.0");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // -------------------------------------------------------------------------
    // POST /api/policies/simulate
    // -------------------------------------------------------------------------

    @Test
    void simulateShouldReturnAllowedWhenWhitelistPolicyMatches() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "version": "4.17.21",
                    "policies": [
                        { "packageName": "lodash", "versionPattern": "*", "policyAction": "WHITELIST", "reason": "Approved" }
                    ]
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"ALLOWED\"");
        assertThat(response.getBody()).contains("\"wins\":true");
    }

    @Test
    void simulateShouldReturnBlockedWhenBlacklistPolicyMatches() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "version": "4.17.21",
                    "policies": [
                        { "packageName": "lodash", "versionPattern": "*", "policyAction": "BLACKLIST", "reason": "Forbidden" }
                    ]
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"BLOCKED\"");
    }

    @Test
    void simulateShouldResolveConflictExactVersionBeatsWildcard() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "version": "4.17.21",
                    "policies": [
                        { "packageName": "lodash", "versionPattern": "*", "policyAction": "BLACKLIST", "reason": "Forbidden by default" },
                        { "packageName": "lodash", "versionPattern": "4.17.21", "policyAction": "WHITELIST", "reason": "Version approved" }
                    ]
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"ALLOWED\"");
        assertThat(response.getBody()).contains("\"wins\":true");
        assertThat(response.getBody()).contains("\"wins\":false");
    }

    @Test
    void simulateShouldReturnNoMatchWhenNoPolicyMatches() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "version": "4.17.21",
                    "policies": [
                        { "packageName": "react", "versionPattern": "*", "policyAction": "BLACKLIST", "reason": "Autre package" }
                    ]
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"NO_MATCH\"");
    }

    @Test
    void simulateShouldMatchPrefixWildcardPattern() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "version": "4.17.21",
                    "policies": [
                        { "packageName": "lodash", "versionPattern": "4.x", "policyAction": "WHITELIST", "reason": "Series 4 approved" }
                    ]
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"decision\":\"ALLOWED\"");
    }

    @Test
    void simulateShouldReturn400WhenBodyMissingVersion() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "policies": []
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void simulateShouldReturn400WhenBodyMissingEcosystem() {
        String body = """
                {
                    "packageName": "lodash",
                    "version": "1.0.0",
                    "policies": []
                }
                """;

        ResponseEntity<String> response = postSimulate(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private ResponseEntity<String> getResponse(String path) {
        try {
            return restClient.get()
                    .uri("http://localhost:" + port + path)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    private ResponseEntity<String> postSimulate(String jsonBody) {
        try {
            return restClient.post()
                    .uri("http://localhost:" + port + "/api/policies/simulate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(jsonBody)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }
}
