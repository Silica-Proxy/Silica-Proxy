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
import com.silicaproxy.dao.client.VulnerabilityGitClient;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;

class GitOpsSyncServiceTest extends BaseIntegrationTest {

    @TempDir
    static Path tempDir;

    private final GitOpsSyncService gitOpsSyncService;
    private final JdbcClient jdbcClient;
    private final VulnerabilitySyncStatusService syncStatusService;

    @MockitoBean
    private VulnerabilityGitClient gitClient;

    @Autowired
    GitOpsSyncServiceTest(
            GitOpsSyncService gitOpsSyncService,
            JdbcClient jdbcClient,
            VulnerabilitySyncStatusService syncStatusService) {
        this.gitOpsSyncService = gitOpsSyncService;
        this.jdbcClient = jdbcClient;
        this.syncStatusService = syncStatusService;
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.gitops.enabled", () -> "true");
        registry.add("silicaproxy.gitops.repository-url", () -> "https://github.com/fake/gitops.git");
        registry.add("silicaproxy.gitops.directory-path", () -> tempDir.toAbsolutePath().toString());
        registry.add("silicaproxy.gitops.sync-interval-minutes", () -> 10);
    }

    @BeforeEach
    void setup() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE shedlock RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldSyncCompanyPoliciesWithWildcards() throws Exception {
        // Prepare fake YAML files
        String npmYaml = """
                rules:
                  - package: "lodash"
                    version: "4.17.21"
                    action: "BLOCK"
                    reason: "CVE-2020-8203"
                  - package: "jquery"
                    version: "1.x"
                    action: "ALLOW"
                    reason: "Exception approved"
                  - package: "shelljs"
                    version: "*"
                    action: "BLOCK"
                    reason: "Globally forbidden"
                """;
        
        Files.writeString(tempDir.resolve("npm.yaml"), npmYaml);

        // Mock Git client to do nothing as the file is already placed in tempDir
        doAnswer(invocation -> null)
                .when(gitClient).syncRepository(any(), any(), any());

        // Execute sync
        gitOpsSyncService.syncCompanyPolicies();

        // Verify database
        List<Map<String, Object>> policies = jdbcClient.sql("SELECT * FROM company_policies ORDER BY id").query().listOfRows();
        assertThat(policies).hasSize(3);

        Map<String, Object> p1 = policies.get(0);
        assertThat(p1.get("package_name")).isEqualTo("lodash");
        assertThat(p1.get("version_pattern")).isEqualTo("4.17.21");
        assertThat(p1.get("policy_action")).isEqualTo("BLOCK");

        Map<String, Object> p2 = policies.get(1);
        assertThat(p2.get("package_name")).isEqualTo("jquery");
        assertThat(p2.get("version_pattern")).isEqualTo("1.%"); // 1.x translated
        assertThat(p2.get("policy_action")).isEqualTo("ALLOW");

        Map<String, Object> p3 = policies.get(2);
        assertThat(p3.get("package_name")).isEqualTo("shelljs");
        assertThat(p3.get("version_pattern")).isEqualTo("%"); // * translated
        assertThat(p3.get("policy_action")).isEqualTo("BLOCK");

        // Verify ShedLock table via a separate test or check manually if we can trigger scheduler, 
        // but testing ShedLock directly is easier by just verifying the lock is created if called via scheduler,
        // but here we call the method directly. Let's just trust ShedLock config, or we can check its presence if executed.
        // Actually since we call it directly, ShedLock AOP might intercept it if we call the proxy.
        List<Map<String, Object>> locks = jdbcClient.sql("SELECT * FROM shedlock WHERE name = 'gitops_sync_lock'").query().listOfRows();
        assertThat(locks).hasSize(1);

        // The 3 rules from npm.yaml (only file present) must constitute 100% of the total volume.
        VulnerabilitySyncStatusService.JobStatus job = syncStatusService.getJobs().get("gitops-sync");
        assertThat(job).isNotNull();
        assertThat(job.itemsTotal()).isEqualTo(3L);
        assertThat(job.itemsProcessed()).isEqualTo(3L);
        assertThat(job.progressPercent()).isEqualTo(100.0);
    }

}
