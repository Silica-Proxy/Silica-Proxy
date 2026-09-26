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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Maven artifacts served by a repository manager must be identified under their real
 * {@code groupId:artifactId} : the repository prefix must not be folded into the groupId, and a
 * resource whose file name does not repeat the coordinates must not be taken for an artifact.
 */
class UrlParserServiceMavenLayoutsTest {

    private final UrlParserService urlParserService = new UrlParserService();

    @ParameterizedTest
    @CsvSource({
        // Nexus 3, with and without the "/nexus" context path
        "https://nexus.corp/repository/maven-public/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar, org.slf4j:slf4j-api, 2.0.9",
        "https://nexus.corp/nexus/repository/maven-proxy/com/example/lib/1.0.0/lib-1.0.0.pom, com.example:lib, 1.0.0",
        // Nexus 2
        "https://nexus.corp/nexus/content/repositories/releases/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar, org.apache.commons:commons-lang3, 3.14.0",
        "https://nexus.corp/nexus/content/groups/public/junit/junit/4.13.2/junit-4.13.2.jar, junit:junit, 4.13.2",
        // Artifactory
        "https://artifactory.corp/artifactory/MavenCentral/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar, org.slf4j:slf4j-api, 2.0.9",
        "https://acme.jfrog.io/artifactory/libs-release/com/acme/core/3.1/core-3.1.jar, com.acme:core, 3.1",
        // GitLab, project and group endpoints, with and without a relative URL root
        "https://gitlab.corp/api/v4/projects/42/packages/maven/com/acme/lib/1.2.0/lib-1.2.0.jar, com.acme:lib, 1.2.0",
        "https://gitlab.corp/api/v4/groups/7/-/packages/maven/com/acme/lib/1.2.0/lib-1.2.0.pom, com.acme:lib, 1.2.0",
        "https://corp.example/gitlab/api/v4/projects/42/packages/maven/com/acme/lib/1.2.0/lib-1.2.0.jar, com.acme:lib, 1.2.0",
        // AWS CodeArtifact
        "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/maven/releases/com/acme/lib/2.0/lib-2.0.jar, com.acme:lib, 2.0",
        // Azure Artifacts, with and without project
        "https://pkgs.dev.azure.com/acme/platform/_packaging/feed/maven/v1/com/acme/lib/2.0/lib-2.0.jar, com.acme:lib, 2.0",
        "https://pkgs.dev.azure.com/acme/_packaging/feed/maven/v1/com/acme/lib/2.0/lib-2.0.jar, com.acme:lib, 2.0",
        // GitHub Packages
        "https://maven.pkg.github.com/octo-org/octo-repo/com/octo/lib/1.0.0/lib-1.0.0.jar, com.octo:lib, 1.0.0",
        // Google Maven, JitPack, Nexus 2 at the root (Sonatype OSSRH)
        "https://dl.google.com/dl/android/maven2/androidx/core/core/1.12.0/core-1.12.0.aar, androidx.core:core, 1.12.0",
        "https://maven.google.com/androidx/core/core/1.12.0/core-1.12.0.pom, androidx.core:core, 1.12.0",
        "https://jitpack.io/com/github/jitpack/gradle-simple/1.0/gradle-simple-1.0.jar, com.github.jitpack:gradle-simple, 1.0",
        "https://s01.oss.sonatype.org/content/repositories/releases/io/acme/lib/1.0/lib-1.0.jar, io.acme:lib, 1.0",
        "https://repo.internal/content/groups/public/io/acme/lib/1.0/lib-1.0.jar, io.acme:lib, 1.0",
        // classifier, Gradle module metadata, timestamped and plain SNAPSHOT files
        "https://nexus.corp/repository/maven-public/com/acme/lib/1.0/lib-1.0-sources.jar, com.acme:lib, 1.0",
        "https://nexus.corp/repository/maven-public/com/acme/lib/1.0/lib-1.0.module, com.acme:lib, 1.0",
        "https://nexus.corp/repository/snapshots/com/acme/lib/1.0-SNAPSHOT/lib-1.0-20240101.123456-1.jar, com.acme:lib, 1.0-SNAPSHOT",
        "https://nexus.corp/repository/snapshots/com/acme/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.pom, com.acme:lib, 1.0-SNAPSHOT"
    })
    void shouldIdentifyArtifactBehindRepositoryPrefix(String url, String expectedName, String expectedVersion) {
        ParsedPackage parsed = urlParserService.parseUrl(url);

        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo(expectedName);
        assertThat(parsed.version()).isEqualTo(expectedVersion);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        // file name does not repeat the artifactId
        "https://nexus.corp/repository/maven-public/com/acme/lib/1.0/other-1.0.jar",
        // file version differs from the version directory
        "https://nexus.corp/repository/maven-public/com/acme/lib/1.0/lib-1.1.jar",
        "https://repo.internal/libs/com/acme/lib/1.0/lib-1.0.1.jar",
        // a non-Maven resource that merely has the shape
        "https://cdn.example.com/static/assets/foo/1.0/bundle.zip",
        // known prefix but no groupId left : must not fall back to the one-segment reading
        "https://nexus.corp/repository/x/lib/1.0/lib-1.0.jar",
        // metadata and checksums behind a known prefix
        "https://nexus.corp/repository/maven-public/com/acme/lib/maven-metadata.xml",
        "https://nexus.corp/repository/maven-public/com/acme/lib/1.0/lib-1.0.jar.sha1"
    })
    void shouldNotIdentifyMismatchingOrNonArtifactPath(String url) {
        assertThat(urlParserService.parseUrl(url).isIdentified()).isFalse();
    }

    @Test
    void hostSpecificLayoutMustNotApplyOnOtherHosts() {
        // "/maven/{repo}/" is CodeArtifact's prefix only on amazonaws.com : elsewhere "maven" is
        // an ordinary one-segment repository prefix.
        ParsedPackage parsed = urlParserService.parseUrl("https://repo.internal/maven/com/acme/lib/1.0/lib-1.0.jar");

        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("com.acme:lib");
        assertThat(parsed.version()).isEqualTo("1.0");
    }
}
