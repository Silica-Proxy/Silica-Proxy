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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class RealToolchainGradleIntegrationTest extends BaseRealToolchainTest {

    // Reuses the developer's already-populated ~/.gradle/wrapper/dists cache when present
    private static final Path SHARED_WRAPPER_DISTS = resolveSharedWrapperDistsCache();

    private static Path resolveSharedWrapperDistsCache() {
        Path realDists = Path.of(System.getProperty("user.home"), ".gradle", "wrapper", "dists");
        if (Files.isDirectory(realDists)) {
            return realDists;
        }
        try {
            return Files.createTempDirectory("silicaproxy-shared-gradle-dists-");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Test
    void shouldResolveFixedVersion() throws Exception {
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:2.0.9");
        assertGradleBuildSucceeds(result);
        assertDecisionCached("org.slf4j:slf4j-api", "2.0.9", "maven", "ALLOW");
    }

    @Test
    void shouldResolveVersionRange() throws Exception {
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:[2.0,3.0)");
        assertGradleBuildSucceeds(result);
        String resolvedVersion = getGradleResolvedVersion(result.output());
        if (resolvedVersion != null) {
            System.out.printf("gradle resolved: org.slf4j:slf4j-api:[2.0,3.0) → version %s%n", resolvedVersion);
            assertDecisionCached("org.slf4j:slf4j-api", resolvedVersion, "maven", "ALLOW");
        }
    }

    @Test
    void shouldResolveWildcardVersion() throws Exception {
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:2.+");
        assertGradleBuildSucceeds(result);
        String resolvedVersion = getGradleResolvedVersion(result.output());
        if (resolvedVersion != null) {
            System.out.printf("gradle resolved: org.slf4j:slf4j-api:2.+ → version %s%n", resolvedVersion);
        }
    }

    @Test
    void shouldResolveLatestRelease() throws Exception {
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:latest.release");
        assertGradleBuildSucceeds(result);
        String resolvedVersion = getGradleResolvedVersion(result.output());
        if (resolvedVersion != null) {
            System.out.printf("gradle resolved: org.slf4j:slf4j-api:latest.release → version %s%n", resolvedVersion);
            assertDecisionCached("org.slf4j:slf4j-api", resolvedVersion, "maven", "ALLOW");
        }
    }

    @Test
    void shouldBlockBlacklistedDependency() throws Exception {
        blacklist("org.slf4j:slf4j-api", "maven");
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:2.0.9");
        assertThat(result.exitCode())
                .withFailMessage("Expected gradle build of blacklisted slf4j-api to fail, but it succeeded:%n%s",
                        result.output())
                .isNotZero();
        assertThat(result.output()).contains("403");
    }

    @Test
    void shouldBlockBlacklistedDependencyWithVersionRange() throws Exception {
        blacklist("org.slf4j:slf4j-api", "maven");
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:[2.0,3.0)");
        assertThat(result.exitCode())
                .withFailMessage("Expected gradle build of blacklisted slf4j-api (version range) to fail, but it succeeded:%n%s",
                        result.output())
                .isNotZero();
        assertThat(result.output()).contains("403");
    }

    @Test
    void shouldBlockOnlySpecificBlacklistedVersion() throws Exception {
        blacklist("org.slf4j:slf4j-api", "maven", "2.0.9");

        GradleResult blockedResult = gradleBuild("org.slf4j:slf4j-api:2.0.9");
        assertThat(blockedResult.exitCode())
                .withFailMessage("Expected gradle build of specifically blacklisted slf4j-api:2.0.9 to fail, but it succeeded:%n%s",
                        blockedResult.output())
                .isNotZero();
        assertThat(blockedResult.output()).contains("403");

        GradleResult allowedResult = gradleBuild("org.slf4j:slf4j-api:2.0.13");
        assertThat(allowedResult.exitCode())
                .withFailMessage("Expected gradle build of slf4j-api:2.0.13 (not blacklisted, only 2.0.9 is) to succeed:%n%s",
                        allowedResult.output())
                .isZero();
    }

    @Test
    void shouldBlockOnlySpecificBlacklistedVersionViaRange() throws Exception {
        blacklist("org.slf4j:slf4j-api", "maven", "2.0.9");

        // [2.0.9,2.0.10) contains only 2.0.9 in the real Maven Central sequence
        GradleResult blockedResult = gradleBuild("org.slf4j:slf4j-api:[2.0.9,2.0.10)");
        assertThat(blockedResult.exitCode())
                .withFailMessage("Expected gradle build resolving range to blacklisted slf4j-api:2.0.9 to fail, but it succeeded:%n%s",
                        blockedResult.output())
                .isNotZero();
        assertThat(blockedResult.output()).contains("403");

        // [2.0.8,2.0.9) contains only 2.0.8, which is not blacklisted
        GradleResult allowedResult = gradleBuild("org.slf4j:slf4j-api:[2.0.8,2.0.9)");
        assertThat(allowedResult.exitCode())
                .withFailMessage("Expected gradle build resolving range to slf4j-api:2.0.8 (not blacklisted, only 2.0.9 is) to succeed:%n%s",
                        allowedResult.output())
                .isZero();
    }

    @Test
    void shouldBlockBlacklistedDependencyWithLatestRelease() throws Exception {
        blacklist("org.slf4j:slf4j-api", "maven");
        GradleResult result = gradleBuild("org.slf4j:slf4j-api:latest.release");
        assertThat(result.exitCode())
                .withFailMessage("Expected gradle build of blacklisted slf4j-api (latest.release) to fail, but it succeeded:%n%s",
                        result.output())
                .isNotZero();
        assertThat(result.output()).contains("403");
    }

    private void assertGradleBuildSucceeds(GradleResult result) {
        assertThat(result.exitCode())
                .withFailMessage("gradle build failed:%n%s", result.output())
                .isZero();
    }

    private record GradleResult(int exitCode, String output) {}

    private GradleResult gradleBuild(String dependencyNotation) throws IOException, InterruptedException {
        Path projectDir = Files.createTempDirectory("silicaproxy-real-gradle-");
        Path sourceRoot = Path.of(System.getProperty("user.dir"));

        Files.copy(sourceRoot.resolve("gradlew"), projectDir.resolve("gradlew"), StandardCopyOption.REPLACE_EXISTING);
        assertThat(projectDir.resolve("gradlew").toFile().setExecutable(true)).isTrue();

        Path wrapperDir = projectDir.resolve("gradle").resolve("wrapper");
        Files.createDirectories(wrapperDir);
        Files.copy(sourceRoot.resolve("gradle/wrapper/gradle-wrapper.jar"), wrapperDir.resolve("gradle-wrapper.jar"));
        Files.copy(sourceRoot.resolve("gradle/wrapper/gradle-wrapper.properties"), wrapperDir.resolve("gradle-wrapper.properties"));

        Files.writeString(projectDir.resolve("settings.gradle"), "rootProject.name = 'real-toolchain-check'\n");
        Files.writeString(projectDir.resolve("build.gradle"), """
                plugins {
                    id 'java-library'
                }
                repositories {
                    maven {
                        url 'http://repo1.maven.org/maven2'
                        allowInsecureProtocol = true
                    }
                }
                dependencies {
                    implementation '%s'
                }
                """.formatted(dependencyNotation));

        Path sourceDir = projectDir.resolve("src/main/java");
        Files.createDirectories(sourceDir);
        Files.writeString(sourceDir.resolve("Sample.java"), """
                import org.slf4j.Logger;

                public class Sample {
                    private Logger logger;
                }
                """);

        Path gradleUserHome = Files.createTempDirectory("silicaproxy-gradle-home-");
        Files.createDirectories(gradleUserHome.resolve("wrapper"));
        Files.createSymbolicLink(gradleUserHome.resolve("wrapper").resolve("dists"), SHARED_WRAPPER_DISTS);

        ProcessBuilder processBuilder = new ProcessBuilder(
                "./gradlew", "build", "--no-daemon",
                "-Dhttp.proxyHost=127.0.0.1", "-Dhttp.proxyPort=" + port)
                .directory(projectDir.toFile())
                .redirectErrorStream(true);
        processBuilder.environment().put("GRADLE_USER_HOME", gradleUserHome.toString());
        Process process = processBuilder.start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = process.waitFor(5, TimeUnit.MINUTES);

        assertThat(finished).withFailMessage("Gradle build timed out for %s", dependencyNotation).isTrue();
        return new GradleResult(process.exitValue(), output);
    }

    private String getGradleResolvedVersion(String buildOutput) {
        // Gradle shows resolved version in "compileClasspath" or "runtimeClasspath" lines like:
        // +--- org.slf4j:slf4j-api:2.0.13 (selected by rule)
        // or just: +--- org.slf4j:slf4j-api:2.0.13
        Pattern pattern = Pattern.compile("org\\.slf4j:slf4j-api:([\\d.]+)");
        Matcher matcher = pattern.matcher(buildOutput);
        String lastMatch = null;
        while (matcher.find()) {
            lastMatch = matcher.group(1);
        }
        return lastMatch;
    }
}
