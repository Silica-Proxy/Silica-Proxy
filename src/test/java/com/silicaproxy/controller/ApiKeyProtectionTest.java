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
import com.silicaproxy.config.ApiKeyValidator;
import com.silicaproxy.service.policy.GitOpsSyncService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncScheduler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

// End-to-end coverage of the @RequiresApiKey / ApiKeyInterceptor / ApiKeyValidator chain
// across every endpoint listed in PROTECTION-ENDPOINTS.md, in the same spirit as
// SecurityConfigurationTest for SSRF: toggles the feature on for this class only via the
// real ApiKeyValidator bean, keeping BaseIntegrationTest's default (disabled) for every
// other, unrelated controller test in the shared context.
class ApiKeyProtectionTest extends BaseIntegrationTest {

    private static final String READ_KEY = "test-read-key";
    private static final String ACTION_KEY = "test-action-key";

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();
    private final JdbcClient jdbcClient;
    private final ApiKeyValidator apiKeyValidator;

    @MockitoBean
    private GitOpsSyncService gitOpsSyncService;

    @MockitoBean
    private VulnerabilitySyncScheduler vulnerabilitySyncScheduler;

    @Autowired
    ApiKeyProtectionTest(JdbcClient jdbcClient, ApiKeyValidator apiKeyValidator) {
        this.jdbcClient = jdbcClient;
        this.apiKeyValidator = apiKeyValidator;
    }

    @BeforeEach
    void enableApiAuthAndResetJobs() {
        apiKeyValidator.setEnabled(true);
        jdbcClient.sql("""
                UPDATE sync_status
                SET status = 'PENDING', last_start_time = NULL, last_end_time = NULL,
                    duration_ms = NULL, error_message = NULL, items_processed = 0,
                    items_total = NULL, next_run_time = NULL
                """).update();
    }

    @AfterEach
    void disableApiAuth() {
        apiKeyValidator.setEnabled(false);
    }

    @Test
    void monitoringHealthShouldAcceptWithoutKeyAndAllowWithReadOrActionKey() {
        assertThat(get("/api/monitoring/health", null).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("/api/monitoring/health", "wrong-key").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("/api/monitoring/health", READ_KEY).getStatusCode()).isEqualTo(HttpStatus.OK);
        // ACTION is a superset of READ: the action key must also unlock read-only endpoints.
        assertThat(get("/api/monitoring/health", ACTION_KEY).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // -------------------------------------------------------------------------
    // READ scope
    // -------------------------------------------------------------------------

    @Test
    void monitoringCaCertShouldRejectWithoutKeyAndAllowWithReadKey() {
        assertThat(get("/api/monitoring/ca-cert", null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(get("/api/monitoring/ca-cert", READ_KEY).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void packageSearchShouldRejectWithoutKeyAndAllowWithReadKey() {
        assertThat(get("/api/packages/search?packageName=lodash", null).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(get("/api/packages/search?packageName=lodash", READ_KEY).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void vulnerabilitySyncStatusShouldRejectWithoutKeyAndAllowWithReadKey() {
        assertThat(get("/api/vulnerabilities/sync/status", null).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(get("/api/vulnerabilities/sync/status", READ_KEY).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void policyEvaluateShouldRejectWithoutKeyAndAllowWithReadKey() {
        String path = "/api/policies/evaluate?ecosystem=npm&packageName=lodash&version=4.17.21";
        assertThat(get(path, null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(get(path, READ_KEY).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void policySimulateShouldRejectWithoutKeyAndAllowWithReadKey() {
        String body = """
                {
                    "ecosystem": "npm",
                    "packageName": "lodash",
                    "version": "4.17.21",
                    "policies": []
                }
                """;

        assertThat(post("/api/policies/simulate", null, body).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/policies/simulate", READ_KEY, body).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // -------------------------------------------------------------------------
    // ACTION scope
    // -------------------------------------------------------------------------

    @Test
    void vulnerabilitySyncForceShouldRejectWithoutKeyAndAllowWithActionKey() {
        assertThat(post("/api/vulnerabilities/sync/force", null, "").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/vulnerabilities/sync/force", READ_KEY, "").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/vulnerabilities/sync/force", ACTION_KEY, "").getStatusCode())
                .isEqualTo(HttpStatus.ACCEPTED);
    }

    @Test
    void gitopsSyncForceShouldRejectWithoutKeyAndAllowWithActionKey() {
        assertThat(post("/api/gitops/sync/force", null, "").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/gitops/sync/force", READ_KEY, "").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/gitops/sync/force", ACTION_KEY, "").getStatusCode())
                .isEqualTo(HttpStatus.ACCEPTED);
    }

    private ResponseEntity<String> get(String path, String bearerKey) {
        try {
            return restClient.get()
                    .uri("http://localhost:" + port + path)
                    .headers(headers -> addBearerToken(headers, bearerKey))
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    private ResponseEntity<String> post(String path, String bearerKey, String body) {
        try {
            return restClient.post()
                    .uri("http://localhost:" + port + path)
                    .headers(headers -> addBearerToken(headers, bearerKey))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    private static void addBearerToken(HttpHeaders headers, String bearerKey) {
        if (bearerKey != null) {
            headers.setBearerAuth(bearerKey);
        }
    }
}
