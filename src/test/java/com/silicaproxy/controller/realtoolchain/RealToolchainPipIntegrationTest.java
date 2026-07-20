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


package com.silicaproxy.controller.realtoolchain;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class   RealToolchainPipIntegrationTest extends BaseRealToolchainTest {

    @Test
    void shouldInstallFixedVersion() throws Exception {
        assertPipInstallSucceeds("requests==2.31.0");
        assertDecisionCached("requests", "2.31.0", "pypi", "ALLOW");
    }

    @Test
    void shouldInstallVersionRange() throws Exception {
        String workdir = assertPipInstallSucceeds("requests>=2.0,<3.0");
        String resolvedVersion = getPipResolvedVersion(workdir, "requests");
        if (resolvedVersion != null) {
            System.out.printf("pip resolved: requests>=2.0,<3.0 → version %s%n", resolvedVersion);
            assertDecisionCached("requests", resolvedVersion, "pypi", "ALLOW");
        }
    }

    @Test
    void shouldInstallCompatibleRelease() throws Exception {
        String workdir = assertPipInstallSucceeds("requests~=2.31");
        String resolvedVersion = getPipResolvedVersion(workdir, "requests");
        if (resolvedVersion != null) {
            System.out.printf("pip resolved: requests~=2.31 → version %s%n", resolvedVersion);
            assertDecisionCached("requests", resolvedVersion, "pypi", "ALLOW");
        }
    }

    @Test
    void shouldInstallUnpinned() throws Exception {
        String workdir = assertPipInstallSucceeds("requests");
        String resolvedVersion = getPipResolvedVersion(workdir, "requests");
        if (resolvedVersion != null) {
            System.out.printf("pip resolved: requests → version %s%n", resolvedVersion);
            assertDecisionCached("requests", resolvedVersion, "pypi", "ALLOW");
        }
    }

    @Test
    void shouldBlockBlacklistedPackage() throws Exception {
        blacklist("requests", "pypi");
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = pipInstall("requests==2.31.0", workdir);
        assertThat(result.getExitCode())
                .withFailMessage("Expected pip install of blacklisted requests to fail, but it succeeded:%n%s",
                        result.getStdout())
                .isNotZero();
        assertThat(result.getStdout() + result.getStderr()).contains("403");
    }

    @Test
    void shouldBlockBlacklistedPackageWithVersionRange() throws Exception {
        blacklist("requests", "pypi");
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = pipInstall("requests>=2.0,<3.0", workdir);
        assertThat(result.getExitCode())
                .withFailMessage("Expected pip install of blacklisted requests (version range) to fail, but it succeeded:%n%s",
                        result.getStdout())
                .isNotZero();
        assertThat(result.getStdout() + result.getStderr()).contains("403");
    }

    @Test
    void shouldBlockOnlySpecificBlacklistedVersion() throws Exception {
        blacklist("requests", "pypi", "2.31.0");

        String blockedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult blockedResult = pipInstall("requests==2.31.0", blockedWorkdir);
        assertThat(blockedResult.getExitCode())
                .withFailMessage("Expected pip install of specifically blacklisted requests==2.31.0 to fail, but it succeeded:%n%s",
                        blockedResult.getStdout())
                .isNotZero();
        assertThat(blockedResult.getStdout() + blockedResult.getStderr()).contains("403");

        String allowedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult allowedResult = pipInstall("requests==2.30.0", allowedWorkdir);
        assertThat(allowedResult.getExitCode())
                .withFailMessage("Expected pip install of requests==2.30.0 (not blacklisted, only 2.31.0 is) to succeed:%n%s",
                        allowedResult.getStdout() + allowedResult.getStderr())
                .isZero();
    }

    @Test
    void shouldBlockOnlySpecificBlacklistedVersionViaRange() throws Exception {
        blacklist("requests", "pypi", "2.31.0");

        // >=2.31.0,<2.32.0 resolves only to 2.31.0 in the real PyPI sequence
        String blockedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult blockedResult = pipInstall("requests>=2.31.0,<2.32.0", blockedWorkdir);
        assertThat(blockedResult.getExitCode())
                .withFailMessage("Expected pip install resolving range to blacklisted requests==2.31.0 to fail, but it succeeded:%n%s",
                        blockedResult.getStdout())
                .isNotZero();
        assertThat(blockedResult.getStdout() + blockedResult.getStderr()).contains("403");

        // >=2.30.0,<2.31.0 resolves only to 2.30.0, which is not blacklisted
        String allowedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult allowedResult = pipInstall("requests>=2.30.0,<2.31.0", allowedWorkdir);
        assertThat(allowedResult.getExitCode())
                .withFailMessage("Expected pip install resolving range to requests==2.30.0 (not blacklisted, only 2.31.0 is) to succeed:%n%s",
                        allowedResult.getStdout() + allowedResult.getStderr())
                .isZero();
    }

    @Test
    void shouldBlockOnlyVersionWithHighCvssVulnerability() throws Exception {
        injectVulnerability("requests", "pypi", "2.31.0", 9.5);

        String blockedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult blockedResult = pipInstall("requests==2.31.0", blockedWorkdir);
        assertThat(blockedResult.getExitCode())
                .withFailMessage("Expected pip install of requests==2.31.0 (CVSS 9.5 vulnerability) to fail, but it succeeded:%n%s",
                        blockedResult.getStdout())
                .isNotZero();
        assertThat(blockedResult.getStdout() + blockedResult.getStderr()).contains("403");

        String allowedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult allowedResult = pipInstall("requests==2.30.0", allowedWorkdir);
        assertThat(allowedResult.getExitCode())
                .withFailMessage("Expected pip install of requests==2.30.0 (no vulnerability, only 2.31.0 is affected) to succeed:%n%s",
                        allowedResult.getStdout() + allowedResult.getStderr())
                .isZero();
    }

    @Test
    void shouldBlockOnlyVersionWithHighCvssVulnerabilityViaRange() throws Exception {
        injectVulnerability("requests", "pypi", "2.31.0", 9.5);

        // >=2.31.0,<2.32.0 resolves only to 2.31.0 in the real PyPI sequence
        String blockedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult blockedResult = pipInstall("requests>=2.31.0,<2.32.0", blockedWorkdir);
        assertThat(blockedResult.getExitCode())
                .withFailMessage("Expected pip install resolving range to vulnerable requests==2.31.0 to fail, but it succeeded:%n%s",
                        blockedResult.getStdout())
                .isNotZero();
        assertThat(blockedResult.getStdout() + blockedResult.getStderr()).contains("403");

        // >=2.30.0,<2.31.0 resolves only to 2.30.0, which has no injected vulnerability
        String allowedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult allowedResult = pipInstall("requests>=2.30.0,<2.31.0", allowedWorkdir);
        assertThat(allowedResult.getExitCode())
                .withFailMessage("Expected pip install resolving range to requests==2.30.0 (no vulnerability, only 2.31.0 is affected) to succeed:%n%s",
                        allowedResult.getStdout() + allowedResult.getStderr())
                .isZero();
    }

    @Test
    void shouldBlockBlacklistedPackageWithUnpinned() throws Exception {
        blacklist("requests", "pypi");
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = pipInstall("requests", workdir);
        assertThat(result.getExitCode())
                .withFailMessage("Expected pip install of blacklisted requests (unpinned) to fail, but it succeeded:%n%s",
                        result.getStdout())
                .isNotZero();
        assertThat(result.getStdout() + result.getStderr()).contains("403");
    }

    private String assertPipInstallSucceeds(String spec) throws IOException, InterruptedException {
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = pipInstall(spec, workdir);
        assertThat(result.getExitCode())
                .withFailMessage("pip install %s failed:%n%s%n%s", spec, result.getStdout(), result.getStderr())
                .isZero();
        return workdir;
    }

    private Container.ExecResult pipInstall(String spec, String workdir) throws IOException, InterruptedException {
        String command = "mkdir -p " + workdir + " && pip install"
                + " --index-url http://pypi.org/simple/"
                + " --proxy http://host.testcontainers.internal:" + loomProxyServer.getProxyPort()
                + " --trusted-host pypi.org --trusted-host files.pythonhosted.org"
                + " --target " + workdir
                + " --no-cache-dir '" + spec + "'";
        return pipContainer.execInContainer("sh", "-c", command);
    }

    private String getPipResolvedVersion(String workdir, String packageName) throws IOException, InterruptedException {
        try {
            Container.ExecResult result = pipContainer.execInContainer("sh", "-c",
                    "cat " + workdir + "/" + packageName + "-*.dist-info/METADATA");
            if (result.getExitCode() == 0) {
                Pattern versionPattern = Pattern.compile("^Version: (.+)$", Pattern.MULTILINE);
                Matcher matcher = versionPattern.matcher(result.getStdout());
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (Exception e) {
            System.out.printf("⚠ Could not extract pip version for %s from %s: %s%n", packageName, workdir, e.getMessage());
        }
        return null;
    }
}
