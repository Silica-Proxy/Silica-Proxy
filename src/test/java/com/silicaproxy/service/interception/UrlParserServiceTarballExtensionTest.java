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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class UrlParserServiceTarballExtensionTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "https://registry.corp.example/pool/abc/internal-lib.tgz",
            "https://registry.corp.example/pool/abc/internal-lib.tgz?token=x",
            "https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz"})
    void shouldRecognizeTgzPath(String url) {
        assertThat(UrlParserService.hasNpmTarballExtension(url)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://registry.corp.example/internal-lib",
            "https://registry.corp.example/internal-lib?x=.tgz",
            "https://npm.pkg.github.com/download/@owner/pkg/1.0.0/abcdef",
            "not a uri with spaces.tgz"})
    void shouldRejectNonTgzOrInvalidUrl(String url) {
        assertThat(UrlParserService.hasNpmTarballExtension(url)).isFalse();
    }
}
