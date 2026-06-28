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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class GitOpsControllerTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();
    private final JdbcClient jdbcClient;

    @MockitoBean
    private GitOpsSyncService gitOpsSyncService;

    @Autowired
    GitOpsControllerTest(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void resetGitopsJob() {
        // artifactsentry.gitops.enabled=true by default (application.yaml) in this shared context.
        jdbcClient.sql("UPDATE sync_status SET status = 'PENDING' WHERE job_id = 'gitops-sync'").update();
    }

    @Test
    void shouldForceGitOpsSyncSuccessfullyWhenIdle() {
        ResponseEntity<String> response = postForce();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).contains("GitOps synchronization started");
        verify(gitOpsSyncService, timeout(1000)).syncCompanyPolicies();
    }

    @Test
    void shouldReturnConflictWhenGitOpsSyncIsAlreadyRunning() {
        jdbcClient.sql("UPDATE sync_status SET status = 'RUNNING', last_start_time = CURRENT_TIMESTAMP WHERE job_id = 'gitops-sync'").update();

        ResponseEntity<String> response = postForce();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).contains("GitOps synchronization is already running");
        verifyNoInteractions(gitOpsSyncService);
    }

    private ResponseEntity<String> postForce() {
        try {
            return restClient.post()
                    .uri("http://localhost:" + port + "/api/gitops/sync/force")
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }
}
