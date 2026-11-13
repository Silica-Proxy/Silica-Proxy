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

import com.silicaproxy.dao.client.VulnerabilityGitClient;
import com.silicaproxy.dao.policy.GitOpsDao;
import com.silicaproxy.model.entity.CompanyPolicy;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for yml/yaml extension support in GitOpsSyncService.
 * Instantiates the service directly (no Spring context, no ShedLock) to test
 * file resolution logic in isolation.
 */
class GitOpsSyncServiceExtensionTest {

    @TempDir
    Path tempDir;

    private GitOpsSyncService service;
    private GitOpsDao gitOpsDao;
    private VulnerabilityGitClient gitClient;
    private MeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        gitClient = mock(VulnerabilityGitClient.class);
        gitOpsDao = mock(GitOpsDao.class);
        VulnerabilitySyncStatusService syncStatusService = mock(VulnerabilitySyncStatusService.class);
        meterRegistry = new SimpleMeterRegistry();

        SilicaProxyProperties.GitOpsProperties gitopsProps = new SilicaProxyProperties.GitOpsProperties(
                true,
                "https://fake.git/repo.git",
                tempDir.toAbsolutePath().toString(),
                null,
                10
        );

        SilicaProxyProperties properties = mock(SilicaProxyProperties.class);
        org.mockito.Mockito.when(properties.gitops()).thenReturn(gitopsProps);

        doNothing().when(gitClient).syncRepository(any(), any(), any());

        service = new GitOpsSyncService(properties, gitClient, gitOpsDao, syncStatusService, meterRegistry);
    }

    @Test
    void shouldReadNpmYamlExtension() throws Exception {
        Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "lodash"
                    version: "4.17.21"
                    action: "block"
                    reason: "CVE-2020-8203"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("npm"), captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("lodash");

        assertThat(meterRegistry.get(Metrics.GITOPS_POLICIES_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "npm").counter().count()).isEqualTo(1.0);
        assertThat(meterRegistry.get(Metrics.GITOPS_RUNS_METRIC)
                .tag(Metrics.TAG_OUTCOME, Metrics.OUTCOME_SUCCESS).counter().count()).isEqualTo(1.0);
        assertThat(meterRegistry.find(Metrics.GITOPS_FRESHNESS_METRIC).gauge()).isNotNull();
    }

    @Test
    void shouldReadNpmYmlExtension() throws Exception {
        Files.writeString(tempDir.resolve("npm.yml"), """
                rules:
                  - package: "event-stream"
                    version: "3.3.6"
                    action: "block"
                    reason: "Supply-chain attack"
                  - package: "lodash"
                    version: "*"
                    action: "allow"
                    reason: "Approved"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("npm"), captor.capture());
        assertThat(captor.getValue()).hasSize(2);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("event-stream");
        assertThat(captor.getValue().get(1).packageName()).isEqualTo("lodash");
    }

    @Test
    void shouldReadPypiYamlExtension() throws Exception {
        Files.writeString(tempDir.resolve("pypi.yaml"), """
                rules:
                  - package: "requests"
                    version: "*"
                    action: "allow"
                    reason: "Standard library"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("pypi"), captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("requests");
    }

    @Test
    void shouldNormalizePypiRuleNamesPerPep503() throws Exception {
        Files.writeString(tempDir.resolve("pypi.yaml"), """
                rules:
                  - package: "typing_extensions"
                    version: "*"
                    action: "block"
                    reason: "PEP 503"
                  - package: "Django*"
                    version: "*"
                    action: "block"
                    reason: "wildcard kept"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("pypi"), captor.capture());
        assertThat(captor.getValue()).extracting(CompanyPolicy::packageName)
                .containsExactly("typing-extensions", "django*");
    }

    @Test
    void shouldReadPypiYmlExtension() throws Exception {
        Files.writeString(tempDir.resolve("pypi.yml"), """
                rules:
                  - package: "flask"
                    version: "3.*"
                    action: "allow"
                    reason: "Approved framework"
                  - package: "malicious-pkg"
                    version: "1.0"
                    action: "block"
                    reason: "Compromised"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("pypi"), captor.capture());
        assertThat(captor.getValue()).hasSize(2);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("flask");
    }

    @Test
    void shouldReadMavenYamlExtension() throws Exception {
        Files.writeString(tempDir.resolve("maven.yaml"), """
                rules:
                  - package: "commons-collections:commons-collections"
                    version: "3.2.1"
                    action: "block"
                    reason: "CVE-2015-6420"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("maven"), captor.capture());
        assertThat(captor.getValue()).hasSize(1);
    }

    @Test
    void shouldReadMavenYmlExtension() throws Exception {
        Files.writeString(tempDir.resolve("maven.yml"), """
                rules:
                  - package: "org.slf4j:slf4j-api"
                    version: "*"
                    action: "allow"
                    reason: "Approved logging"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("maven"), captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("org.slf4j:slf4j-api");
    }

    @Test
    void shouldPreferYamlOverYmlForNpm() throws Exception {
        Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "from-yaml"
                    version: "1.0"
                    action: "block"
                    reason: "From .yaml"
                """);
        Files.writeString(tempDir.resolve("npm.yml"), """
                rules:
                  - package: "from-yml"
                    version: "2.0"
                    action: "allow"
                    reason: "From .yml"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("npm"), captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("from-yaml");
    }

    @Test
    void shouldPreferYamlOverYmlForPypi() throws Exception {
        Files.writeString(tempDir.resolve("pypi.yaml"), """
                rules:
                  - package: "from-yaml"
                    version: "1.0"
                    action: "block"
                    reason: "From .yaml"
                """);
        Files.writeString(tempDir.resolve("pypi.yml"), """
                rules:
                  - package: "from-yml"
                    version: "2.0"
                    action: "allow"
                    reason: "From .yml"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("pypi"), captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).packageName()).isEqualTo("from-yaml");
    }

    @Test
    void shouldSyncAllEcosystemsWithMixedExtensions() throws Exception {
        // Simulate a repository with mixed extensions (e.g. GitLab uses .yml, local dev uses .yaml)
        Files.writeString(tempDir.resolve("npm.yml"), """
                rules:
                  - package: "shelljs"
                    version: "0.8.*"
                    action: "block"
                    reason: "Forbidden"
                """);
        Files.writeString(tempDir.resolve("pypi.yaml"), """
                rules:
                  - package: "requests"
                    version: "*"
                    action: "allow"
                    reason: "Standard library"
                  - package: "malicious-pkg"
                    version: "1.0"
                    action: "block"
                    reason: "Compromised"
                """);
        Files.writeString(tempDir.resolve("maven.yml"), """
                rules:
                  - package: "commons-collections:commons-collections"
                    version: "3.2.1"
                    action: "block"
                    reason: "CVE-2015-6420"
                """);

        service.syncCompanyPolicies();

        ArgumentCaptor<List<CompanyPolicy>> npmCaptor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("npm"), npmCaptor.capture());
        assertThat(npmCaptor.getValue()).hasSize(1);
        assertThat(npmCaptor.getValue().get(0).packageName()).isEqualTo("shelljs");

        ArgumentCaptor<List<CompanyPolicy>> pypiCaptor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("pypi"), pypiCaptor.capture());
        assertThat(pypiCaptor.getValue()).hasSize(2);

        ArgumentCaptor<List<CompanyPolicy>> mavenCaptor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("maven"), mavenCaptor.capture());
        assertThat(mavenCaptor.getValue()).hasSize(1);
    }

    @Test
    void shouldStoreExpiryOfDateAndDateTimeRules() throws Exception {
        Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "date-only"
                    version: "*"
                    action: "allow"
                    reason: "date alone, unquoted"
                    expires: 2999-12-31
                  - package: "date-time"
                    version: "*"
                    action: "allow"
                    reason: "date-time with offset"
                    expires: "2999-12-31T18:00:00+02:00"
                  - package: "local-date-time"
                    version: "*"
                    action: "allow"
                    reason: "date-time without offset, read as UTC"
                    expires: "2999-12-31T18:00:00"
                  - package: "permanent"
                    version: "*"
                    action: "block"
                    reason: "no expires"
                """);

        service.syncCompanyPolicies();

        List<CompanyPolicy> policies = captureNpmPolicies();
        assertThat(policies).extracting(CompanyPolicy::packageName, CompanyPolicy::expiresAt).containsExactly(
                tuple("date-only", Instant.parse("3000-01-01T00:00:00Z")),
                tuple("date-time", Instant.parse("2999-12-31T16:00:00Z")),
                tuple("local-date-time", Instant.parse("2999-12-31T18:00:00Z")),
                tuple("permanent", null));
    }

    @Test
    void shouldSkipAlreadyExpiredRules() throws Exception {
        Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "expired"
                    version: "*"
                    action: "allow"
                    reason: "over"
                    expires: "2000-01-01"
                  - package: "running"
                    version: "*"
                    action: "allow"
                    reason: "still valid"
                    expires: "2999-01-01"
                """);

        service.syncCompanyPolicies();

        assertThat(captureNpmPolicies()).extracting(CompanyPolicy::packageName).containsExactly("running");
    }

    @Test
    void shouldFailClosedOnUnreadableExpiry() throws Exception {
        Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "typo-allow"
                    version: "*"
                    action: "allow"
                    reason: "a typo must not make the exception permanent"
                    expires: "31/12/2026"
                  - package: "typo-block"
                    version: "*"
                    action: "block"
                    reason: "a typo must not drop the block"
                    expires: "31/12/2026"
                """);

        service.syncCompanyPolicies();

        List<CompanyPolicy> policies = captureNpmPolicies();
        assertThat(policies).extracting(CompanyPolicy::packageName, CompanyPolicy::expiresAt)
                .containsExactly(tuple("typo-block", null));
    }

    @Test
    void shouldKeepMostRestrictiveRuleOnDuplicateKeyWithoutFailingTheSync() throws Exception {
        Files.writeString(tempDir.resolve("npm.yaml"), """
                rules:
                  - package: "lodash"
                    version: "*"
                    action: "allow"
                    reason: "temporary exception"
                    expires: "2999-01-01"
                  - package: "lodash"
                    version: "*"
                    action: "block"
                    reason: "permanent block"
                  - package: "two-blocks"
                    version: "1.x"
                    action: "block"
                    reason: "short block"
                    expires: "2998-01-01"
                  - package: "two-blocks"
                    version: "1.*"
                    action: "block"
                    reason: "long block"
                    expires: "2999-01-01"
                  - package: "two-allows"
                    version: "*"
                    action: "allow"
                    reason: "long allow"
                    expires: "2999-01-01"
                  - package: "two-allows"
                    version: "*"
                    action: "allow"
                    reason: "short allow"
                    expires: "2998-01-01"
                  - package: "twin"
                    version: "1.0.0"
                    action: "block"
                    reason: "first"
                  - package: "twin"
                    version: "1.0.0"
                    action: "block"
                    reason: "second"
                """);
        Files.writeString(tempDir.resolve("pypi.yaml"), """
                rules:
                  - package: "PyYAML"
                    version: "*"
                    action: "allow"
                    reason: "approved"
                  - package: "pyyaml"
                    version: "*"
                    action: "block"
                    reason: "same project once PEP 503-normalized"
                """);

        service.syncCompanyPolicies();

        // "1.x" and "1.*" are the same stored pattern ("1.%"), hence a duplicate.
        assertThat(captureNpmPolicies()).extracting(CompanyPolicy::packageName, CompanyPolicy::reason).containsExactly(
                tuple("lodash", "permanent block"),
                tuple("two-blocks", "long block"),
                tuple("two-allows", "short allow"),
                tuple("twin", "first"));

        ArgumentCaptor<List<CompanyPolicy>> pypiCaptor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("pypi"), pypiCaptor.capture());
        assertThat(pypiCaptor.getValue()).extracting(CompanyPolicy::packageName, CompanyPolicy::policyAction)
                .containsExactly(tuple("pyyaml", "BLOCK"));
        assertThat(meterRegistry.get(Metrics.GITOPS_RUNS_METRIC)
                .tag(Metrics.TAG_OUTCOME, Metrics.OUTCOME_SUCCESS).counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldSyncNothingWhenNoFilePresent() {
        service.syncCompanyPolicies();

        verify(gitOpsDao, never()).replaceCompanyPolicies(any(), any());
    }

    private List<CompanyPolicy> captureNpmPolicies() {
        ArgumentCaptor<List<CompanyPolicy>> captor = policyCaptor();
        verify(gitOpsDao).replaceCompanyPolicies(eq("npm"), captor.capture());
        return captor.getValue();
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<List<CompanyPolicy>> policyCaptor() {
        return ArgumentCaptor.forClass((Class<List<CompanyPolicy>>) (Class<?>) List.class);
    }
}
