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

import com.silicaproxy.config.Metrics;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.client.VulnerabilityGitClient;
import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.dao.policy.GitOpsDao;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.SeverityThreshold;
import com.silicaproxy.model.dto.Verdict;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.interception.ParsedPackage;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import io.micrometer.core.instrument.MeterRegistry;
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
import java.util.Optional;

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
    private final MeterRegistry meterRegistry;
    private final SilicaProxyProperties properties;
    private final GitOpsDao gitOpsDao;
    private final DecisionDao decisionDao;

    @MockitoBean
    private VulnerabilityGitClient gitClient;

    @Autowired
    GitOpsSyncServiceTest(
            GitOpsSyncService gitOpsSyncService,
            JdbcClient jdbcClient,
            VulnerabilitySyncStatusService syncStatusService,
            MeterRegistry meterRegistry,
            SilicaProxyProperties properties,
            GitOpsDao gitOpsDao,
            DecisionDao decisionDao) {
        this.gitOpsSyncService = gitOpsSyncService;
        this.jdbcClient = jdbcClient;
        this.syncStatusService = syncStatusService;
        this.meterRegistry = meterRegistry;
        this.properties = properties;
        this.gitOpsDao = gitOpsDao;
        this.decisionDao = decisionDao;
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
                  - package: "weird-pkg"
                    version: "1.0.0-xyz"
                    action: "BLOCK"
                    reason: "Literal 'x' in a pre-release suffix must not be treated as a wildcard"
                """;
        
        Files.writeString(tempDir.resolve("npm.yaml"), npmYaml);

        // Mock Git client to do nothing as the file is already placed in tempDir
        doAnswer(invocation -> null)
                .when(gitClient).syncRepository(any(), any(), any());

        // Execute sync
        double before = meterRegistry.find(Metrics.GITOPS_POLICIES_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "npm").counter() == null ? 0.0
                : meterRegistry.get(Metrics.GITOPS_POLICIES_METRIC)
                        .tag(Metrics.TAG_ECOSYSTEM, "npm").counter().count();
        gitOpsSyncService.syncCompanyPolicies();

        // Verify database
        List<Map<String, Object>> policies = jdbcClient.sql("SELECT * FROM company_policies ORDER BY id").query().listOfRows();
        assertThat(policies).hasSize(4);

        assertThat(meterRegistry.get(Metrics.GITOPS_POLICIES_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "npm").counter().count() - before).isEqualTo(4.0);
        assertThat(meterRegistry.get(Metrics.GITOPS_RUNS_METRIC)
                .tag(Metrics.TAG_OUTCOME, Metrics.OUTCOME_SUCCESS).counter().count())
                .isGreaterThanOrEqualTo(1.0);

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

        Map<String, Object> p4 = policies.get(3);
        assertThat(p4.get("package_name")).isEqualTo("weird-pkg");
        // A literal 'x' not in a trailing ".x" wildcard segment must be left untouched, not
        // corrupted into "1.0.0-%yz".
        assertThat(p4.get("version_pattern")).isEqualTo("1.0.0-xyz");
        assertThat(p4.get("policy_action")).isEqualTo("BLOCK");

        // Verify ShedLock table via a separate test or check manually if we can trigger scheduler, 
        // but testing ShedLock directly is easier by just verifying the lock is created if called via scheduler,
        // but here we call the method directly. Let's just trust ShedLock config, or we can check its presence if executed.
        // Actually since we call it directly, ShedLock AOP might intercept it if we call the proxy.
        List<Map<String, Object>> locks = jdbcClient.sql("SELECT * FROM shedlock WHERE name = 'gitops_sync_lock'").query().listOfRows();
        assertThat(locks).hasSize(1);

        // The 4 rules from npm.yaml (only file present) must constitute 100% of the total volume.
        VulnerabilitySyncStatusService.JobStatus job = syncStatusService.getJobs().get("gitops-sync");
        assertThat(job).isNotNull();
        assertThat(job.itemsTotal()).isEqualTo(4L);
        assertThat(job.itemsProcessed()).isEqualTo(4L);
        assertThat(job.progressPercent()).isEqualTo(100.0);
    }

    @Test
    void shouldBlockInternalNamespacesOfEveryEcosystemAgainstDependencyConfusion() throws Exception {
        // Behind a repository manager, only its remote repositories reach the proxy : an internal
        // package name requested here is necessarily fetched from a public registry. These
        // namespace rules, as documented in the README, must block it whatever the version.
        Path npmYaml = Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "@moncorp/*"
                    version: "*"
                    action: "block"
                    reason: "Internal npm scope"
                  - package: "moncorp-*"
                    version: "*"
                    action: "block"
                    reason: "Internal unscoped npm prefix"
                """);
        Path pypiYaml = Files.writeString(tempDir.resolve("pypi.yaml"), """
                rules:
                  - package: "MonCorp_*"
                    version: "*"
                    action: "block"
                    reason: "Internal PyPI prefix"
                """);
        Path mavenYaml = Files.writeString(tempDir.resolve("maven.yaml"), """
                rules:
                  - package: "com.moncorp:*"
                    version: "*"
                    action: "block"
                    reason: "Internal Maven groupId"
                  - package: "com.moncorp.*"
                    version: "*"
                    action: "block"
                    reason: "Internal Maven sub-groups"
                """);
        doAnswer(invocation -> null).when(gitClient).syncRepository(any(), any(), any());

        try {
            // Built outside Spring, hence without the ShedLock aspect : the lock row the other
            // sync of this class leaves behind (or the setup truncates) cannot skip this run.
            new GitOpsSyncService(properties, gitClient, gitOpsDao, syncStatusService, meterRegistry)
                    .syncCompanyPolicies();
        } finally {
            // tempDir is shared by the whole class : the other test expects npm.yaml alone.
            Files.delete(npmYaml);
            Files.delete(pypiYaml);
            Files.delete(mavenYaml);
        }

        // The PyPI rule is stored PEP 503-normalized, like the names the proxy identifies.
        assertThat(jdbcClient.sql("SELECT package_name FROM company_policies WHERE ecosystem = 'pypi'")
                .query(String.class).list()).containsExactly("moncorp-*");

        assertBlocked(new ParsedPackage("@moncorp/utils", "99.0.0", "npm"), "Internal npm scope");
        assertBlocked(new ParsedPackage("moncorp-auth", "99.0.0", "npm"), "Internal unscoped npm prefix");
        // Any spelling a PyPI client may request is normalized before the decision.
        assertBlocked(new ParsedPackage("MonCorp.Auth", "99.0.0", "pypi"), "Internal PyPI prefix");
        assertBlocked(new ParsedPackage("moncorp_auth", "99.0.0", "pypi"), "Internal PyPI prefix");
        assertBlocked(new ParsedPackage("com.moncorp:auth", "99.0.0", "maven"), "Internal Maven groupId");
        assertBlocked(new ParsedPackage("com.moncorp.platform:auth", "99.0.0", "maven"), "Internal Maven sub-groups");

        // Names merely sharing the prefix are not internal.
        assertNoDecision(new ParsedPackage("@moncorpevil/utils", "1.0.0", "npm"));
        assertNoDecision(new ParsedPackage("moncorpauth", "1.0.0", "npm"));
        assertNoDecision(new ParsedPackage("moncorpauth", "1.0.0", "pypi"));
        assertNoDecision(new ParsedPackage("com.moncorpevil:auth", "1.0.0", "maven"));
        // A rule is scoped to its own ecosystem.
        assertNoDecision(new ParsedPackage("@moncorp/utils", "1.0.0", "pypi"));
    }

    private void assertBlocked(ParsedPackage pkg, String reason) {
        Optional<DecisionResult> decision = evaluate(pkg);
        assertThat(decision).as("%s/%s", pkg.ecosystem(), pkg.packageName()).isPresent();
        assertThat(decision.get().sourceType()).isEqualTo(DecisionSource.COMPANY_POLICY);
        assertThat(decision.get().result()).isEqualTo(Verdict.BLOCK);
        assertThat(decision.get().reason()).isEqualTo(reason);
    }

    private void assertNoDecision(ParsedPackage pkg) {
        assertThat(evaluate(pkg)).as("%s/%s", pkg.ecosystem(), pkg.packageName()).isEmpty();
    }

    private Optional<DecisionResult> evaluate(ParsedPackage pkg) {
        return decisionDao.evaluateDecision(pkg.packageName(), pkg.version(), pkg.ecosystem(),
                SeverityThreshold.blockingFrom(7.0));
    }
}
