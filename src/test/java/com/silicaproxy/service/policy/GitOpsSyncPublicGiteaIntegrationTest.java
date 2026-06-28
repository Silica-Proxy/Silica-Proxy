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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link GitOpsSyncService} against a real Gitea public repository.
 * Validates that policies are cloned and stored in the database without any authentication token.
 */
class GitOpsSyncPublicGiteaIntegrationTest extends BaseIntegrationTest {

    private final GitOpsSyncService gitOpsSyncService;
    private final JdbcClient jdbcClient;

    @Autowired
    GitOpsSyncPublicGiteaIntegrationTest(GitOpsSyncService gitOpsSyncService, JdbcClient jdbcClient) {
        this.gitOpsSyncService = gitOpsSyncService;
        this.jdbcClient = jdbcClient;
    }

    @DynamicPropertySource
    static void configureGitops(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.gitops.enabled", () -> "true");
        registry.add("silicaproxy.gitops.repository-url", () -> GiteaContainerSetup.publicRepoUrl);
        registry.add("silicaproxy.gitops.directory-path", () -> GiteaContainerSetup.publicGitopsDir.toString());
        registry.add("silicaproxy.gitops.clone-token", () -> "");
        registry.add("silicaproxy.gitops.sync-interval-minutes", () -> 10);
    }

    @BeforeEach
    void cleanup() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE shedlock RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldSyncPoliciesFromPublicRepoWithoutToken() {
        gitOpsSyncService.syncCompanyPolicies();

        List<Map<String, Object>> policies = jdbcClient.sql(
                "SELECT * FROM company_policies ORDER BY package_name").query().listOfRows();
        assertThat(policies).hasSize(2);

        Map<String, Object> jquery = policies.get(0);
        assertThat(jquery.get("package_name")).isEqualTo("jquery");
        assertThat(jquery.get("version_pattern")).isEqualTo("1.%");
        assertThat(jquery.get("policy_action")).isEqualTo("ALLOW");
        assertThat(jquery.get("updated_by")).isEqualTo("gitops_sync");

        Map<String, Object> lodash = policies.get(1);
        assertThat(lodash.get("package_name")).isEqualTo("lodash");
        assertThat(lodash.get("version_pattern")).isEqualTo("4.17.21");
        assertThat(lodash.get("policy_action")).isEqualTo("BLOCK");
    }

}
