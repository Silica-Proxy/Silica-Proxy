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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RealToolchainNpmIntegrationTest extends BaseRealToolchainTest {

    @Test
    void shouldInstallFixedVersion() throws Exception {
        assertNpmInstallSucceeds("lodash@4.17.21");
        assertDecisionCached("lodash", "4.17.21", "npm", "ALLOW");
    }

    @Test
    void shouldInstallVersionRange() throws Exception {
        String workdir = assertNpmInstallSucceeds("lodash@^4.17.0");
        String resolvedVersion = getNpmResolvedVersion(workdir, "lodash");
        if (resolvedVersion != null) {
            System.out.printf("npm resolved: lodash@^4.17.0 → version %s%n", resolvedVersion);
            assertDecisionCached("lodash", resolvedVersion, "npm", "ALLOW");
        }
    }

    @Test
    void shouldInstallLatest() throws Exception {
        String workdir = assertNpmInstallSucceeds("lodash@latest");
        String resolvedVersion = getNpmResolvedVersion(workdir, "lodash");
        if (resolvedVersion != null) {
            System.out.printf("npm resolved: lodash@latest → version %s%n", resolvedVersion);
            assertDecisionCached("lodash", resolvedVersion, "npm", "ALLOW");
        }
    }

    @Test
    void shouldBlockBlacklistedPackage() throws Exception {
        blacklist("lodash", "npm");
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = npmInstall("lodash@4.17.21", workdir);
        assertThat(result.getExitCode())
                .withFailMessage("Expected npm install of blacklisted lodash to fail, but it succeeded:%n%s",
                        result.getStdout())
                .isNotZero();
        assertThat(result.getStdout() + result.getStderr()).contains("403");
    }

    @Test
    void shouldBlockBlacklistedPackageWithVersionRange() throws Exception {
        blacklist("lodash", "npm");
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = npmInstall("lodash@^4.17.0", workdir);
        assertThat(result.getExitCode())
                .withFailMessage("Expected npm install of blacklisted lodash (version range) to fail, but it succeeded:%n%s",
                        result.getStdout())
                .isNotZero();
        assertThat(result.getStdout() + result.getStderr()).contains("403");
    }

    @Test
    void shouldBlockOnlySpecificBlacklistedVersion() throws Exception {
        blacklist("lodash", "npm", "4.17.21");

        String blockedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult blockedResult = npmInstall("lodash@4.17.21", blockedWorkdir);
        assertThat(blockedResult.getExitCode())
                .withFailMessage("Expected npm install of specifically blacklisted lodash@4.17.21 to fail, but it succeeded:%n%s",
                        blockedResult.getStdout())
                .isNotZero();
        assertThat(blockedResult.getStdout() + blockedResult.getStderr()).contains("403");

        String allowedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult allowedResult = npmInstall("lodash@4.17.20", allowedWorkdir);
        assertThat(allowedResult.getExitCode())
                .withFailMessage("Expected npm install of lodash@4.17.20 (not blacklisted, only 4.17.21 is) to succeed:%n%s",
                        allowedResult.getStdout() + allowedResult.getStderr())
                .isZero();
    }

    @Test
    void shouldBlockOnlySpecificBlacklistedVersionViaRange() throws Exception {
        blacklist("lodash", "npm", "4.17.21");

        // >=4.17.21 <4.17.22 resolves only to 4.17.21 (excludes the later 4.17.23 patch release)
        String blockedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult blockedResult = npmInstall("lodash@>=4.17.21 <4.17.22", blockedWorkdir);
        assertThat(blockedResult.getExitCode())
                .withFailMessage("Expected npm install resolving range to blacklisted lodash@4.17.21 to fail, but it succeeded:%n%s",
                        blockedResult.getStdout())
                .isNotZero();
        assertThat(blockedResult.getStdout() + blockedResult.getStderr()).contains("403");

        // >=4.17.20 <4.17.21 resolves only to 4.17.20, which is not blacklisted
        String allowedWorkdir = "/work/" + UUID.randomUUID();
        Container.ExecResult allowedResult = npmInstall("lodash@>=4.17.20 <4.17.21", allowedWorkdir);
        assertThat(allowedResult.getExitCode())
                .withFailMessage("Expected npm install resolving range to lodash@4.17.20 (not blacklisted, only 4.17.21 is) to succeed:%n%s",
                        allowedResult.getStdout() + allowedResult.getStderr())
                .isZero();
    }

    @Test
    void shouldBlockBlacklistedPackageWithLatest() throws Exception {
        blacklist("lodash", "npm");
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = npmInstall("lodash@latest", workdir);
        assertThat(result.getExitCode())
                .withFailMessage("Expected npm install of blacklisted lodash (latest) to fail, but it succeeded:%n%s",
                        result.getStdout())
                .isNotZero();
        assertThat(result.getStdout() + result.getStderr()).contains("403");
    }

    private String assertNpmInstallSucceeds(String spec) throws IOException, InterruptedException {
        String workdir = "/work/" + UUID.randomUUID();
        Container.ExecResult result = npmInstall(spec, workdir);
        assertThat(result.getExitCode())
                .withFailMessage("npm install %s failed:%n%s%n%s", spec, result.getStdout(), result.getStderr())
                .isZero();
        return workdir;
    }

    private Container.ExecResult npmInstall(String spec, String workdir) throws IOException, InterruptedException {
        String command = "mkdir -p " + workdir + " && npm install '" + spec + "'"
                + " --registry=http://registry.npmjs.org"
                + " --proxy=http://host.testcontainers.internal:" + port
                + " --cache " + workdir + "/.npm-cache"
                + " --prefix " + workdir
                + " --no-fund --no-audit --loglevel=error";
        return npmContainer.execInContainer("sh", "-c", command);
    }

    private String getNpmResolvedVersion(String workdir, String packageName) throws IOException, InterruptedException {
        try {
            Container.ExecResult result = npmContainer.execInContainer("sh", "-c",
                    "cat " + workdir + "/node_modules/" + packageName + "/package.json");
            if (result.getExitCode() == 0) {
                JsonNode json = new ObjectMapper().readTree(result.getStdout());
                return json.get("version").asString();
            }
        } catch (Exception e) {
            // version extraction failed
        }
        return null;
    }
}
