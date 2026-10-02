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


package com.silicaproxy.service.interception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** plugins-artifacts.gradle.org serves "/{groupId}/{artifactId}/{version}/{sha256}/{file}". */
class UrlParserServiceGradlePortalTest {

    private static final String SHA256 = "65c692c67d26c3a04aa5c8107b57dc0535a74a8bba47a0484c4aa7195c8a6cc2";
    private static final String HOST = "https://plugins-artifacts.gradle.org";
    private static final ParsedPackage UNKNOWN = ParsedPackage.unknown(ParsedPackage.UNKNOWN);

    private final UrlParserService urlParserService = new UrlParserService();

    @ParameterizedTest
    @ValueSource(strings = {
            "gradle-versions-plugin-0.64.0.module",
            "gradle-versions-plugin-0.64.0.jar",
            "gradle-versions-plugin-0.64.0.pom",
            "gradle-versions-plugin-0.64.0-sources.jar"})
    void identifiesTheMavenCoordinatesOfAPortalArtifact(String file) {
        ParsedPackage parsed = urlParserService.parseUrl(
                HOST + "/io.github.ben-manes/gradle-versions-plugin/0.64.0/" + SHA256 + "/" + file);

        assertThat(parsed.ecosystem()).isEqualTo(ParsedPackage.MAVEN);
        assertThat(parsed.packageName()).isEqualTo("io.github.ben-manes:gradle-versions-plugin");
        assertThat(parsed.version()).isEqualTo("0.64.0");
    }

    @Test
    void keepsTheDotsOfTheGroupIdAndHandlesLongerVersions() {
        ParsedPackage parsed = urlParserService.parseUrl(
                HOST + "/com.github.spotbugs/com.github.spotbugs.gradle.plugin/6.5.12/" + SHA256
                        + "/com.github.spotbugs.gradle.plugin-6.5.12.pom");

        assertThat(parsed.packageName())
                .isEqualTo("com.github.spotbugs:com.github.spotbugs.gradle.plugin");
        assertThat(parsed.version()).isEqualTo("6.5.12");
    }

    @Test
    void rejectsAFileThatDoesNotRepeatTheCoordinates() {
        assertThat(urlParserService.parseUrl(
                HOST + "/io.github.ben-manes/gradle-versions-plugin/0.64.0/" + SHA256 + "/other-1.0.jar"))
                .isEqualTo(UNKNOWN);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/io.github.ben-manes/gradle-versions-plugin/0.64.0/65c692c6/gradle-versions-plugin-0.64.0.jar",
            "/io.github.ben-manes/gradle-versions-plugin/0.64.0/ZZc692c67d26c3a04aa5c8107b57dc0535a74a8bba47a0484c4aa7195c8a6cc2/gradle-versions-plugin-0.64.0.jar",
            "/io.github.ben-manes/gradle-versions-plugin/0.64.0/gradle-versions-plugin-0.64.0.jar"})
    void rejectsPathsWithoutAContentHashDirectory(String path) {
        assertThat(urlParserService.parseUrl(HOST + path)).isEqualTo(UNKNOWN);
    }

    @Test
    void ignoresChecksumFiles() {
        assertThat(urlParserService.parseUrl(
                HOST + "/io.github.ben-manes/gradle-versions-plugin/0.64.0/" + SHA256
                        + "/gradle-versions-plugin-0.64.0.jar.sha1"))
                .isEqualTo(UNKNOWN);
    }

    @Test
    void theShapeIsRecognisedWhateverTheHost() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://repo.example.com/io.github.ben-manes/gradle-versions-plugin/0.64.0/" + SHA256
                        + "/gradle-versions-plugin-0.64.0.jar");

        assertThat(parsed.ecosystem()).isEqualTo(ParsedPackage.MAVEN);
        assertThat(parsed.packageName()).isEqualTo("io.github.ben-manes:gradle-versions-plugin");
        assertThat(parsed.version()).isEqualTo("0.64.0");
    }

    @Test
    void conventionalRepositoryLayoutsAreReadAsBefore() {
        ParsedPackage nexus = urlParserService.parseUrl(
                "http://192.168.0.20:8081/repository/maven/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar");
        ParsedPackage central = urlParserService.parseUrl(
                "https://repo1.maven.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.pom");

        assertThat(nexus.packageName()).isEqualTo("com.google.guava:guava");
        assertThat(nexus.version()).isEqualTo("33.0.0-jre");
        assertThat(central.packageName()).isEqualTo("com.google.guava:guava");
        assertThat(central.version()).isEqualTo("33.0.0-jre");
    }

    @Test
    void aNonMavenFileWithAHashDirectoryIsStillUnknown() {
        assertThat(urlParserService.parseUrl("https://downloads.example.com/tool/1.0/" + SHA256 + "/readme.txt"))
                .isEqualTo(UNKNOWN);
    }
}
