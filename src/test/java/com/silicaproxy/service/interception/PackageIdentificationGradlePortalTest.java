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

import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import com.silicaproxy.service.interception.PackageIdentificationService.Identification;
import com.silicaproxy.service.interception.PackageIdentificationService.Outcome;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Real URL parser, with the URLs seen while resolving Gradle plugins (plain HTTP when Nexus sends
 * them, HTTPS when the client or a CONNECT tunnel does) : they must be identified as Maven
 * artifacts (EVALUATE), not relayed unchecked (BYPASS).
 */
class PackageIdentificationGradlePortalTest {

    private static final String PORTAL_PATH = "plugins-artifacts.gradle.org/io.github.ben-manes/gradle-versions-plugin/0.64.0/"
            + "65c692c67d26c3a04aa5c8107b57dc0535a74a8bba47a0484c4aa7195c8a6cc2/gradle-versions-plugin-0.64.0";

    private final NpmPackumentIndex npmPackumentIndex = mock(NpmPackumentIndex.class);
    private final HttpHeaders headers = new HttpHeaders();

    private Identification identify(String scheme, String url) {
        when(npmPackumentIndex.isEnabled()).thenReturn(true);
        PackageIdentificationService service = new PackageIdentificationService(new UrlParserService(),
                npmPackumentIndex, new NpmPackumentIndexProperties(true, 1000, 60, 1024 * 1024,
                        UnidentifiedTarballAction.ALLOW));
        return service.identify(scheme + "://" + url, "https://" + url, headers);
    }

    @ParameterizedTest
    @CsvSource({"http,.module", "http,.jar", "http,.pom", "https,.module", "https,.jar", "https,.pom"})
    void gradlePluginArtifactFromThePortalIsEvaluated(String scheme, String extension) {
        Identification id = identify(scheme, PORTAL_PATH + extension);

        assertThat(id.outcome()).isEqualTo(Outcome.EVALUATE);
        assertThat(id.pkg()).isEqualTo(
                new ParsedPackage("io.github.ben-manes:gradle-versions-plugin", "0.64.0", ParsedPackage.MAVEN));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http", "https"})
    void gradlePluginMarkerPomFromThePortalIsEvaluated(String scheme) {
        Identification id = identify(scheme, "plugins.gradle.org/m2/com/github/spotbugs/com.github.spotbugs.gradle.plugin/"
                + "6.5.11/com.github.spotbugs.gradle.plugin-6.5.11.pom");

        assertThat(id.outcome()).isEqualTo(Outcome.EVALUATE);
        assertThat(id.pkg()).isEqualTo(new ParsedPackage(
                "com.github.spotbugs:com.github.spotbugs.gradle.plugin", "6.5.11", ParsedPackage.MAVEN));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http", "https"})
    void portalPathWithoutTheContentHashIsStillBypassed(String scheme) {
        Identification id = identify(scheme, "plugins-artifacts.gradle.org/io.github.ben-manes/gradle-versions-plugin/0.64.0/"
                + "gradle-versions-plugin-0.64.0.module");

        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
    }
}
