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
 * npm tarballs must be identified from their URL alone -- without a relayed packument, as with
 * {@code npm ci} and a lockfile -- on the registry layouts the proxy commonly sees.
 */
class UrlParserServiceNpmLayoutsTest {

    private final UrlParserService urlParserService = new UrlParserService();

    @ParameterizedTest
    @CsvSource({
        // npmjs layout, unchanged
        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz, lodash, 4.17.21",
        "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz, @angular/core, 17.0.0",
        "https://registry.npmjs.org/typescript/-/typescript-5.4.0-beta.tgz, typescript, 5.4.0-beta",
        // Artifactory repository prefix, scoped file written as "-/@scope/name-v.tgz"
        "https://artifactory.corp/artifactory/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz, lodash, 4.17.21",
        "https://artifactory.corp/artifactory/api/npm/npm-remote/@angular/core/-/@angular/core-17.0.0.tgz, @angular/core, 17.0.0",
        // Nexus repository prefix
        "https://nexus.corp/repository/npm-proxy/@types/node/-/node-20.1.0.tgz, @types/node, 20.1.0",
        "https://nexus.corp/repository/npm-proxy/express/-/express-4.19.2.tgz, express, 4.19.2",
        // npm.jsr.io
        "https://npm.jsr.io/~/11/@jsr/std__path/1.0.8.tgz, @jsr/std__path, 1.0.8",
        // GitHub Packages
        "https://npm.pkg.github.com/download/@octo-org/octo-package/1.0.0/5f5d6b2a9c0e1f3a4b5c6d7e8f9a0b1c2d3e4f5a, @octo-org/octo-package, 1.0.0"
    })
    void shouldIdentifyTarballFromUrl(String url, String expectedName, String expectedVersion) {
        ParsedPackage parsed = urlParserService.parseUrl(url);

        assertThat(parsed.ecosystem()).isEqualTo("npm");
        assertThat(parsed.packageName()).isEqualTo(expectedName);
        assertThat(parsed.version()).isEqualTo(expectedVersion);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://registry.npmjs.org/express/invalid/path",
        "https://registry.npmjs.org/express",
        "https://example.com/some/path",
        // file name does not repeat the package name
        "https://artifactory.corp/artifactory/api/npm/npm-remote/lodash/-/underscore-1.0.0.tgz",
        "https://npm.jsr.io/@jsr/std__path"
    })
    void shouldNotIdentifyNonTarballOrMismatchingUrl(String url) {
        assertThat(urlParserService.parseUrl(url).version()).isEqualTo("unknown");
    }

    @Test
    void parseNpmTarballShouldPreferScopedOverPrefixedUnscopedReading() {
        // "/@scope" could otherwise be read as a repository prefix in front of "name".
        assertThat(UrlParserService.parseNpmTarball("/@babel/core/-/core-7.24.0.tgz"))
                .contains(new ParsedPackage("@babel/core", "7.24.0", "npm"));
    }

    @Test
    void parseNpmTarballShouldBeEmptyForUnknownLayout() {
        assertThat(UrlParserService.parseNpmTarball("/blobs/sha256/0123abcd")).isEmpty();
    }
}
