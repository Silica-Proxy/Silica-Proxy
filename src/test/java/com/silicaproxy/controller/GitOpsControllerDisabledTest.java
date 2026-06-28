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
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "silicaproxy.gitops.enabled=false")
class GitOpsControllerDisabledTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();

    @MockitoBean
    private GitOpsSyncService gitOpsSyncService;

    @Test
    void shouldReturnBadRequestWhenGitOpsIsDisabled() {
        ResponseEntity<String> response;
        try {
            response = restClient.post()
                    .uri("http://localhost:" + port + "/api/gitops/sync/force")
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            response = ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("GitOps synchronization is disabled in configuration");
        verifyNoInteractions(gitOpsSyncService);
    }
}
