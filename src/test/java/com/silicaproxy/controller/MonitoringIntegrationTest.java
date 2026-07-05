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
import com.silicaproxy.service.policy.GitOpsSyncService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncScheduler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class MonitoringIntegrationTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();

    @MockitoBean
    private VulnerabilitySyncScheduler vulnerabilitySyncScheduler;

    @MockitoBean
    private GitOpsSyncService gitOpsSyncService;

    private final JdbcClient jdbcClient;

    @Autowired
    MonitoringIntegrationTest(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void setUp() {
        // Reset all jobs to a known baseline (PENDING status)
        jdbcClient.sql("""
            UPDATE sync_status
            SET status = 'PENDING',
                last_start_time = NULL,
                last_end_time = NULL,
                duration_ms = NULL,
                error_message = NULL,
                items_processed = 0,
                next_run_time = NULL
            """).update();
    }

    private void setAllJobsSuccess() {
        Instant now = Instant.now();
        jdbcClient.sql("""
            UPDATE sync_status
            SET status = 'SUCCESS',
                last_start_time = ?,
                last_end_time = ?,
                duration_ms = 1000,
                error_message = NULL,
                items_processed = 10,
                next_run_time = ?
            """)
            .params(
                Timestamp.from(now.minus(5, ChronoUnit.MINUTES)),
                Timestamp.from(now.minus(5, ChronoUnit.MINUTES)),
                Timestamp.from(now.plus(22, ChronoUnit.HOURS))
            ).update();

        // Specialize next run time for GitOps to fit within its configured 10 minute interval
        jdbcClient.sql("""
            UPDATE sync_status
            SET next_run_time = ?
            WHERE job_id = 'gitops-sync'
            """)
            .params(Timestamp.from(now.plus(8, ChronoUnit.MINUTES)))
            .update();
    }

    @Test
    void shouldReturnUpWhenAllComponentsAreOk() {
        setAllJobsSuccess();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/monitoring/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"UP\"");
        assertThat(body).contains("\"database\":{\"status\":\"UP\"");
        assertThat(body).contains("\"vulnerabilitySync\":{\"status\":\"UP\"");
        assertThat(body).contains("\"nextScheduledSync\"");
        assertThat(body).contains("\"gitopsSync\":{\"status\":\"UP\"");
        assertThat(body).contains("\"nextRunTime\"");
        assertThat(body).contains("\"osvIncrementalSync\":{\"status\":\"UP\"");
    }

    // The same per-component checks are also wired into the standard Spring Boot Actuator
    // endpoint (HealthIndicatorsConfig), not just the custom /api/monitoring/health above.
    @Test
    void shouldExposeSameComponentsUnderActuatorHealth() {
        setAllJobsSuccess();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/actuator/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"UP\"");
        assertThat(body).contains("\"database\"");
        assertThat(body).contains("\"vulnerabilitySync\"");
        assertThat(body).contains("\"gitopsSync\"");
        assertThat(body).contains("\"osvIncrementalSync\"");
    }

    @Test
    void shouldReturnDegradedInActuatorHealthWhenOsvIncrementalSyncIsStale() {
        setAllJobsSuccess();
        jdbcClient.sql("""
            UPDATE sync_status
            SET last_end_time = ?
            WHERE job_id = 'osv-npm-incremental'
            """)
            .params(Timestamp.from(Instant.now().minus(4, ChronoUnit.HOURS)))
            .update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/actuator/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"DEGRADED\"");
        assertThat(body).contains("\"osv-npm-incremental_stale\":true");
        assertThat(body).contains("\"osvIncrementalSync\":{\"details\":{");
    }

    @Test
    void shouldIndicateNeverRunWhenJobsHaveNotExecutedYet() {
        // setUp() has already reset all jobs to PENDING with null timestamps
        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/monitoring/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        // Verify that vulnerability jobs have the neverRun flag
        assertThat(body).contains("\"osv-npm_neverRun\":true");
        assertThat(body).contains("\"gitlab_neverRun\":true");
        assertThat(body).contains("\"ghsa_neverRun\":true");
        // Verify that gitopsSync also has the neverRun flag
        assertThat(body).contains("\"neverRun\":true");
        // Even if no job has run yet, the next occurrence must be calculated
        // directly (cron for vulnerabilities, configured interval for GitOps) rather than
        // being absent, so that the operator always knows when the next sync will take place.
        assertThat(body).contains("\"nextScheduledSync\"");
        assertThat(body).contains("\"osv-npm_nextRunTime\"");
        assertThat(body).contains("\"gitopsSync\"");
        assertThat(body).contains("\"nextRunTime\"");
    }

    @Test
    void shouldReturnDownWhenVulnerabilitySyncJobHasFailed() {
        setAllJobsSuccess();

        // Mark Gitlab job as FAILED
        jdbcClient.sql("""
            UPDATE sync_status
            SET status = 'FAILED',
                error_message = 'Failed to clone gitlab repository'
            WHERE job_id = 'gitlab'
            """).update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/monitoring/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"DOWN\"");
        assertThat(body).contains("\"vulnerabilitySync\":{\"status\":\"DOWN\"");
        assertThat(body).contains("Failed to clone gitlab repository");
    }

    @Test
    void shouldReturnDegradedWhenVulnerabilitySyncJobIsStale() {
        setAllJobsSuccess();

        // Set osv-npm last execution to 30 hours ago (limit is 26 hours)
        jdbcClient.sql("""
            UPDATE sync_status
            SET last_end_time = ?
            WHERE job_id = 'osv-npm'
            """)
            .params(Timestamp.from(Instant.now().minus(30, ChronoUnit.HOURS)))
            .update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/monitoring/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"DEGRADED\"");
        assertThat(body).contains("\"vulnerabilitySync\":{\"status\":\"DEGRADED\"");
        assertThat(body).contains("\"osv-npm_stale\":true");
    }

    @Test
    void shouldReturnDownWhenGitOpsSyncHasFailed() {
        setAllJobsSuccess();

        // Mark gitops-sync as FAILED
        jdbcClient.sql("""
            UPDATE sync_status
            SET status = 'FAILED',
                error_message = 'Invalid policy schema'
            WHERE job_id = 'gitops-sync'
            """).update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/monitoring/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"DOWN\"");
        assertThat(body).contains("\"gitopsSync\":{\"status\":\"DOWN\"");
        assertThat(body).contains("Invalid policy schema");
    }

    @Test
    void shouldReturnDegradedWhenGitOpsSyncIsStale() {
        setAllJobsSuccess();

        // Sync interval is 10 mins. Set last execution to 25 mins ago (limit is 2 * 10 mins = 20 mins)
        jdbcClient.sql("""
            UPDATE sync_status
            SET last_end_time = ?
            WHERE job_id = 'gitops-sync'
            """)
            .params(Timestamp.from(Instant.now().minus(25, ChronoUnit.MINUTES)))
            .update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/monitoring/health")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"status\":\"DEGRADED\"");
        assertThat(body).contains("\"gitopsSync\":{\"status\":\"DEGRADED\"");
        assertThat(body).contains("GitOps sync is stale (missed execution intervals)");
    }

    @Test
    void shouldReturnVulnerabilitySyncStatusCorrectly() {
        jdbcClient.sql("""
            UPDATE sync_status
            SET status = 'RUNNING',
                last_start_time = ?,
                items_processed = 150
            WHERE job_id = 'osv-npm'
            """)
            .params(Timestamp.from(Instant.now()))
            .update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/vulnerabilities/sync/status")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"overallStatus\":\"RUNNING\"");
        assertThat(body).contains("\"itemsProcessed\":150");
        assertThat(body).contains("\"status\":\"PENDING\"");
    }

    private ResponseEntity<String> postForce(String path) {
        try {
            return restClient.post()
                    .uri("http://localhost:" + port + path)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    @Test
    void shouldReturnConflictOnForceVulnerabilitySyncWhenRunning() {
        jdbcClient.sql("UPDATE sync_status SET status = 'RUNNING', last_start_time = CURRENT_TIMESTAMP WHERE job_id = 'osv-npm'").update();

        ResponseEntity<String> response = postForce("/api/vulnerabilities/sync/force");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).contains("A vulnerability synchronization job is already running");
    }

    @Test
    void shouldAcceptForceVulnerabilitySyncWhenIdle() {
        ResponseEntity<String> response = postForce("/api/vulnerabilities/sync/force");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).contains("Vulnerability synchronization started");
    }

    @Test
    void shouldReturnConflictOnForceGitOpsSyncWhenRunning() {
        jdbcClient.sql("UPDATE sync_status SET status = 'RUNNING', last_start_time = CURRENT_TIMESTAMP WHERE job_id = 'gitops-sync'").update();

        ResponseEntity<String> response = postForce("/api/gitops/sync/force");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).contains("GitOps synchronization is already running");
    }

    @Test
    void shouldAcceptForceGitOpsSyncWhenIdle() {
        ResponseEntity<String> response = postForce("/api/gitops/sync/force");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).contains("GitOps synchronization started");
    }
}
