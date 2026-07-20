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

import com.silicaproxy.service.interception.UrlParserService.ParsedPackage;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UrlParserServiceTest {

    private final UrlParserService urlParserService = new UrlParserService();

    @Test
    void parseUrl_shouldParseNpmScopedTarball() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.org/@angular/core/-/core-15.0.0.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("@angular/core");
        assertThat(parsed.version()).isEqualTo("15.0.0");
    }

    @Test
    void parseUrl_shouldParseNpmStandardTarball() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.org/express/-/express-4.18.2.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("express");
        assertThat(parsed.version()).isEqualTo("4.18.2");
    }

    @Test
    void parseUrl_shouldParseNpmStandardTarballWithNumericSuffixInName() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.org/blocked-vuln-5346/-/blocked-vuln-5346-1.0.0.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("blocked-vuln-5346");
        assertThat(parsed.version()).isEqualTo("1.0.0");
    }

    @Test
    void parseUrl_shouldParseNpmScopedTarballWithNumericSuffixInName() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.org/@my-scope/my-pkg-2/-/my-pkg-2-1.0.0.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("@my-scope/my-pkg-2");
        assertThat(parsed.version()).isEqualTo("1.0.0");
    }

    @Test
    void parseUrl_shouldReturnUnknownForNpmMetadataRequest() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.org/express");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldReturnUnknownForInvalidNpmPath() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.org/express/invalid/path");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldReturnUnknownForPypiJsonRequest() {
        ParsedPackage parsed = urlParserService.parseUrl("https://pypi.org/pypi/requests/json");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldParsePypiWheel() {
        ParsedPackage parsed = urlParserService.parseUrl("https://files.pythonhosted.org/packages/b0/12/example/requests-2.28.1-py3-none-any.whl");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("requests");
        assertThat(parsed.version()).isEqualTo("2.28.1");
    }

    @Test
    void parseUrl_shouldParsePypiWheelWithDuplicatedAbiTag() {
        // Compiled wheels repeat the ABI tag (e.g. "-cp27-cp27m-"). A greedy version regex
        // backtracks to the LAST "-cp" occurrence and swallows part of the tag into the version
        // ("1.6.0-cp27" instead of "1.6.0"), which then fails every exact-match vulnerability/
        // policy lookup downstream. See tensorflow 1.6.0 on PyPI for a real-world example.
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://files.pythonhosted.org/packages/77/7b/example/tensorflow-1.6.0-cp27-cp27m-macosx_10_11_x86_64.whl");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("tensorflow");
        assertThat(parsed.version()).isEqualTo("1.6.0");
    }

    @Test
    void parseUrl_shouldParsePypiWheelWithBuildTag() {
        // Wheel filenames may include an optional build tag between version and python tag:
        // {name}-{version}-{build tag}-{python tag}-{abi tag}-{platform}.whl. A greedy name
        // group backtracks past the version's leading digit and swallows it into the name,
        // leaving the build tag digit as the captured "version" instead. See sentry 22.3.0 on
        // PyPI ("sentry-22.3.0-0-py38-none-any.whl") for a real-world example.
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://files.pythonhosted.org/packages/23/bf/example/sentry-22.3.0-0-py38-none-any.whl");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("sentry");
        assertThat(parsed.version()).isEqualTo("22.3.0");
    }

    @Test
    void parseUrl_shouldParsePypiWheelWithPrereleaseVersion() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://files.pythonhosted.org/packages/ab/cd/example/my-pkg-2.0.0rc1-py2.py3-none-any.whl");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("my-pkg");
        assertThat(parsed.version()).isEqualTo("2.0.0rc1");
    }

    @Test
    void parseUrl_shouldParsePypiTarGz() {
        ParsedPackage parsed = urlParserService.parseUrl("https://files.pythonhosted.org/packages/source/r/requests/requests-2.28.1.tar.gz");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("requests");
        assertThat(parsed.version()).isEqualTo("2.28.1");
    }

    @Test
    void parseUrl_shouldParsePypiTarGzFromPypiOrgDirectly() {
        ParsedPackage parsed = urlParserService.parseUrl("http://pypi.org/packages/source/b/blocked-pypi-121/blocked-pypi-121-1.0.0.tar.gz");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("blocked-pypi-121");
        assertThat(parsed.version()).isEqualTo("1.0.0");
    }

    @Test
    void parseUrl_shouldParsePypiTarGzFromModernHashBasedPath() {
        // Real PyPI sdist storage is content-addressed (hash directories), not the legacy
        // /packages/source/{letter}/{name}/ layout — this is what pip actually requests today.
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://files.pythonhosted.org/packages/01/f3/936e209267d6ef7510322191003885de524fc48d1b43269810cd589ceaf5/typing_extensions-4.11.0.tar.gz");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("typing_extensions");
        assertThat(parsed.version()).isEqualTo("4.11.0");
    }

    @Test
    void parseUrl_shouldParsePypiTarGzWithHyphenatedNameFromModernHashBasedPath() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://files.pythonhosted.org/packages/70/e5/81f99b9fced59624562ab62a33df639a11b26c582be78864b339dafa420d/blocked-pypi-121-1.0.0.tar.gz");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("blocked-pypi-121");
        assertThat(parsed.version()).isEqualTo("1.0.0");
    }

    @Test
    void parseUrl_shouldReturnUnknownForInvalidPypiPath() {
        ParsedPackage parsed = urlParserService.parseUrl("https://pypi.org/invalid/path");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldParseMavenArtifact() {
        ParsedPackage parsed = urlParserService.parseUrl("https://repo1.maven.org/maven2/org/springframework/spring-core/6.0.0/spring-core-6.0.0.jar");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("org.springframework:spring-core");
        assertThat(parsed.version()).isEqualTo("6.0.0");
    }

    @Test
    void parseUrl_shouldReturnUnknownForInvalidMavenPath() {
        ParsedPackage parsed = urlParserService.parseUrl("https://repo1.maven.org/maven2/invalid");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldReturnUnknownForMavenMetadataXml() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://repo1.maven.org/maven2/dev/kuml/kuml-metamodel-uml/maven-metadata.xml");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldReturnUnknownForMavenChecksumFile() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://repo1.maven.org/maven2/org/springframework/spring-core/6.0.0/spring-core-6.0.0.jar.sha1");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldReturnUnknownForUnknownHost() {
        ParsedPackage parsed = urlParserService.parseUrl("https://example.com/some/path");
        assertThat(parsed.ecosystem()).isEqualTo("unknown");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldHandleMalformedUrl() {
        // This malformed URL will trigger an IllegalArgumentException in URI.create, 
        // which will be caught and result in 'unknown'.
        ParsedPackage parsed = urlParserService.parseUrl("not_a_valid_url");
        assertThat(parsed.ecosystem()).isEqualTo("unknown");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldHandleNullHostOrPath() {
        ParsedPackage parsed = urlParserService.parseUrl("mailto:test@example.com");
        assertThat(parsed.ecosystem()).isEqualTo("unknown");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    // --- Layer 1 : additional known hosts ---

    @Test
    void parseUrl_shouldParseNpmFromNpmjsCom() {
        ParsedPackage parsed = urlParserService.parseUrl("https://registry.npmjs.com/express/-/express-4.18.2.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("express");
        assertThat(parsed.version()).isEqualTo("4.18.2");
    }

    @Test
    void parseUrl_shouldParseNpmFromGithubPackages() {
        ParsedPackage parsed = urlParserService.parseUrl("https://npm.pkg.github.com/@myorg/mypackage/-/mypackage-1.0.0.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("@myorg/mypackage");
        assertThat(parsed.version()).isEqualTo("1.0.0");
    }

    @Test
    void parseUrl_shouldParseMavenFromApacheRepo() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("org.apache.commons:commons-lang3");
        assertThat(parsed.version()).isEqualTo("3.12.0");
    }

    @Test
    void parseUrl_shouldReturnUnknownForPypiJsonFromLegacyPythonOrg() {
        ParsedPackage parsed = urlParserService.parseUrl("https://pypi.python.org/pypi/requests/json");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldStillApplyNpmChecksOnSpoofedDomainWithNpmPath() {
        ParsedPackage parsed = urlParserService.parseUrl("https://my-npmjs.org/express/-/express-4.18.2.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("express");
        assertThat(parsed.version()).isEqualTo("4.18.2");
    }

    // --- Couche 2 : fallback structurel — Maven ---

    @Test
    void parseUrl_shouldParseMavenFromSpringRepo() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "http://repo.spring.io/release/org/springframework/spring-core/5.3.20/spring-core-5.3.20.jar");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("org.springframework:spring-core");
        assertThat(parsed.version()).isEqualTo("5.3.20");
    }

    @Test
    void parseUrl_shouldParseMavenFromGradlePluginRepo() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://plugins.gradle.org/m2/com/example/plugin/1.0/plugin-1.0.jar");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("com.example:plugin");
        assertThat(parsed.version()).isEqualTo("1.0");
    }

    @Test
    void parseUrl_shouldParseMavenPomFromUnknownRepo() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://my.internal/libs-release/com/acme/lib/2.0/lib-2.0.pom");
        assertThat(parsed.ecosystem()).isEqualTo("maven");
        assertThat(parsed.packageName()).isEqualTo("com.acme:lib");
        assertThat(parsed.version()).isEqualTo("2.0");
    }

    // --- Couche 2 : fallback structurel — npm ---

    @Test
    void parseUrl_shouldParseNpmTarballFromPrivateRegistry() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://my-verdaccio.internal/express/-/express-4.18.2.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("express");
        assertThat(parsed.version()).isEqualTo("4.18.2");
    }

    @Test
    void parseUrl_shouldParseNpmScopedTarballFromPrivateRegistry() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://my-verdaccio.internal/@myorg/mylib/-/mylib-1.0.0.tgz");
        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo("@myorg/mylib");
        assertThat(parsed.version()).isEqualTo("1.0.0");
    }

    @Test
    void parseUrl_shouldNotDetectNpmMetadataOnUnknownHost() {
        ParsedPackage parsed = urlParserService.parseUrl("https://unknown-cdn.com/express");
        assertThat(parsed.ecosystem()).isEqualTo("unknown");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    // --- Couche 2 : fallback structurel — PyPI ---

    @Test
    void parseUrl_shouldReturnUnknownForPypiJsonFromPrivateMirror() {
        ParsedPackage parsed = urlParserService.parseUrl("https://my-devpi.internal/pypi/requests/json");
        assertThat(parsed.ecosystem()).isEqualTo("unknown");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }

    @Test
    void parseUrl_shouldParsePypiWheelFromPrivateMirror() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://my-devpi.internal/packages/r/requests/requests-2.28.1-py3-none-any.whl");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("requests");
        assertThat(parsed.version()).isEqualTo("2.28.1");
    }

    @Test
    void parseUrl_shouldParsePypiTarGzFromModernHashBasedPathOnPrivateMirror() {
        ParsedPackage parsed = urlParserService.parseUrl(
                "https://my-devpi.internal/packages/ab/cd/deadbeef1234/requests-2.28.1.tar.gz");
        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo("requests");
        assertThat(parsed.version()).isEqualTo("2.28.1");
    }

    // --- Layer 2 : unknown host, unrecognizable path ---

    @Test
    void parseUrl_shouldReturnUnknownForUnrecognizedPathOnUnknownHost() {
        ParsedPackage parsed = urlParserService.parseUrl("https://cdn.example.com/files/some-binary.exe");
        assertThat(parsed.ecosystem()).isEqualTo("unknown");
        assertThat(parsed.packageName()).isEqualTo("unknown");
        assertThat(parsed.version()).isEqualTo("unknown");
    }
}
