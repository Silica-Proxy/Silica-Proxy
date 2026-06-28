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


package com.silicaproxy.service.policy;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link GitOpsSyncService} against a real Gitea private repository
 * accessed without an authentication token.
 * Validates that the sync fails gracefully (no policies stored, status marked FAILED)
 * when the token is absent — proving that the token in
 * {@link GitOpsSyncPrivateGiteaIntegrationTest} is what actually grants access.
 */
class GitOpsSyncPrivateNoTokenIntegrationTest extends BaseIntegrationTest {

    private final GitOpsSyncService gitOpsSyncService;
    private final JdbcClient jdbcClient;
    private final VulnerabilitySyncStatusService syncStatusService;

    @Autowired
    GitOpsSyncPrivateNoTokenIntegrationTest(
            GitOpsSyncService gitOpsSyncService,
            JdbcClient jdbcClient,
            VulnerabilitySyncStatusService syncStatusService) {
        this.gitOpsSyncService = gitOpsSyncService;
        this.jdbcClient = jdbcClient;
        this.syncStatusService = syncStatusService;
    }

    @DynamicPropertySource
    static void configureGitops(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.gitops.enabled", () -> "true");
        registry.add("silicaproxy.gitops.repository-url", () -> GiteaContainerSetup.privateRepoUrl);
        registry.add("silicaproxy.gitops.directory-path", () -> GiteaContainerSetup.privateNoTokenGitopsDir.toString());
        registry.add("silicaproxy.gitops.clone-token", () -> "");
        registry.add("silicaproxy.gitops.sync-interval-minutes", () -> 10);
    }

    @BeforeEach
    void cleanup() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE shedlock RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldFailToSyncFromPrivateRepoWithoutToken() {
        gitOpsSyncService.syncCompanyPolicies();

        // Git clone rejected (401): no policies stored
        assertThat(jdbcClient.sql("SELECT * FROM company_policies").query().listOfRows()).isEmpty();

        // Sync task recorded as FAILED, confirming the token is what grants access
        VulnerabilitySyncStatusService.JobStatus status = syncStatusService.getJobs().get("gitops-sync");
        assertThat(status).isNotNull();
        assertThat(status.status()).isEqualTo("FAILED");
        assertThat(status.errorMessage()).isNotBlank();
    }
}
