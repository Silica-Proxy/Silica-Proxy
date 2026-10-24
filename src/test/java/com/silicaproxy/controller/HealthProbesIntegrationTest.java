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
import com.zaxxer.hikari.HikariDataSource;
import com.silicaproxy.service.policy.GitOpsSyncService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncScheduler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

// The liveness/readiness probes (management.endpoint.health.group.*) only depend on the JVM and
// the database : a failed synchronization must not take the proxy out of the load balancer.
class HealthProbesIntegrationTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();

    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    @MockitoBean
    private VulnerabilitySyncScheduler vulnerabilitySyncScheduler;

    @MockitoBean
    private GitOpsSyncService gitOpsSyncService;

    private final JdbcClient jdbcClient;

    private final HikariDataSource dataSource;

    @Autowired
    HealthProbesIntegrationTest(JdbcClient jdbcClient, HikariDataSource dataSource) {
        this.jdbcClient = jdbcClient;
        this.dataSource = dataSource;
    }

    @BeforeEach
    void setAllJobsSuccess() {
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
                Timestamp.from(now.plus(8, ChronoUnit.MINUTES))
            ).update();
    }

    // Back to the state of a fresh database, so the stale/failed jobs set here do not leak into
    // the other test classes of the same fork.
    @AfterEach
    void resetJobs() {
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

    private ResponseEntity<String> get(String path) {
        try {
            return restClient.get()
                    .uri("http://localhost:" + port + path)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    // Top-level status of a health response (the components carry their own "status" too).
    private String status(ResponseEntity<String> response) {
        return jsonMapper.readTree(response.getBody()).path("status").asString();
    }

    @Test
    void shouldKeepReadinessUpWhenGitLabSyncHasFailed() {
        jdbcClient.sql("""
            UPDATE sync_status
            SET status = 'FAILED',
                error_message = 'Connect timed out: gitlab.com'
            WHERE job_id = 'gitlab'
            """).update();

        ResponseEntity<String> readiness = get("/actuator/health/readiness");
        assertThat(readiness.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(readiness)).isEqualTo("UP");
        assertThat(readiness.getBody()).contains("\"db\"").doesNotContain("vulnerabilitySync");

        ResponseEntity<String> liveness = get("/actuator/health/liveness");
        assertThat(liveness.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(liveness)).isEqualTo("UP");

        // The failure is reported by the sync group, as a warning that does not fail the HTTP check
        ResponseEntity<String> sync = get("/actuator/health/sync");
        assertThat(sync.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(sync)).isEqualTo("DEGRADED");
        assertThat(sync.getBody()).contains("Connect timed out: gitlab.com");

        // The root aggregate degrades too, without going DOWN (HTTP 200)
        ResponseEntity<String> root = get("/actuator/health");
        assertThat(root.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(root)).isEqualTo("DEGRADED");
    }

    @Test
    void shouldReportSyncDownWhenEveryOsvSourceIsStaleWithoutFailingReadiness() {
        Timestamp longAgo = Timestamp.from(Instant.now().minus(50, ChronoUnit.HOURS));
        jdbcClient.sql("""
            UPDATE sync_status
            SET last_start_time = ?, last_end_time = ?
            WHERE job_id LIKE 'osv-%'
            """)
            .params(longAgo, longAgo)
            .update();

        ResponseEntity<String> sync = get("/actuator/health/sync");
        assertThat(sync.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(sync.getBody()).contains("No OSV source has synchronized successfully for more than 48h");

        assertThat(get("/actuator/health/readiness").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("/actuator/health/liveness").getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // "Stops" the database for the application : no new connection is accepted and the open
    // ones are closed, while the container keeps running for the next tests.
    @Test
    void shouldReportReadinessDownWhenDatabaseIsUnreachable() throws SQLException, InterruptedException {
        String adminUrl = postgres.getJdbcUrl().replace("/" + postgres.getDatabaseName(), "/postgres");
        try (Connection admin = DriverManager.getConnection(adminUrl, postgres.getUsername(), postgres.getPassword());
             Statement statement = admin.createStatement()) {
            statement.execute("ALTER DATABASE \"" + postgres.getDatabaseName() + "\" WITH ALLOW_CONNECTIONS false");
            try {
                statement.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '"
                        + postgres.getDatabaseName() + "' AND pid <> pg_backend_pid()");

                ResponseEntity<String> readiness = get("/actuator/health/readiness");
                assertThat(readiness.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
                assertThat(status(readiness)).isEqualTo("DOWN");

                // Liveness does not depend on the database : restarting the pod would not fix it
                assertThat(get("/actuator/health/liveness").getStatusCode()).isEqualTo(HttpStatus.OK);
            } finally {
                statement.execute("ALTER DATABASE \"" + postgres.getDatabaseName() + "\" WITH ALLOW_CONNECTIONS true");
                // The pooled connections were closed by the server : replace them all
                dataSource.getHikariPoolMXBean().softEvictConnections();
            }
        }

        // Readiness comes back UP on its own once the database accepts connections again
        long deadline = System.nanoTime() + 15_000_000_000L;
        ResponseEntity<String> readiness = get("/actuator/health/readiness");
        while (readiness.getStatusCode() != HttpStatus.OK && System.nanoTime() < deadline) {
            Thread.sleep(200);
            readiness = get("/actuator/health/readiness");
        }
        assertThat(readiness.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
