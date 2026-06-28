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


package com.silicaproxy.dao.client;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.PackageMetadataResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

class RegistryClientTest extends BaseIntegrationTest {

    private final RegistryClient registryClient;

    @Autowired
    RegistryClientTest(RegistryClient registryClient) {
        this.registryClient = registryClient;
    }

    @BeforeEach
    void resetWiremock() {
        wireMock.resetAll();
    }

    @Test
    void shouldExtractNpmMetadataCorrectly() {
        // Mock of NPM response for lodash
        wireMock.stubFor(get(urlEqualTo("/lodash"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "time": {
                                "4.17.21": "2021-05-02T12:00:00.000Z"
                              },
                              "versions": {
                                "4.17.21": {
                                  "name": "lodash",
                                  "version": "4.17.21",
                                  "deprecated": "Use lodash-es instead"
                                }
                              }
                            }
                            """)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("lodash", "4.17.21", "npm");

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2021-05-02T12:00:00Z"));
        assertThat(result.get().isDeprecated()).isTrue();
        assertThat(result.get().deprecationReason()).isEqualTo("Use lodash-es instead");
    }

    @Test
    void shouldExtractPypiMetadataCorrectly() {
        // Mock of PyPI response for requests
        wireMock.stubFor(get(urlEqualTo("/pypi/requests/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "releases": {
                                "2.25.1": [
                                  {
                                    "upload_time_iso_8601": "2020-12-16T18:00:00Z",
                                    "yanked": true
                                  }
                                ]
                              }
                            }
                            """)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("requests", "2.25.1", "pypi");

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2020-12-16T18:00:00Z"));
        assertThat(result.get().isDeprecated()).isTrue();
        assertThat(result.get().deprecationReason()).isEqualTo("Yanked from PyPI registry");
    }

    @Test
    void shouldExtractMavenMetadataCorrectly() {
        // Mock of Maven HEAD response for spring-core
        wireMock.stubFor(head(urlEqualTo("/maven2/org/springframework/spring-core/6.0.0/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Last-Modified", "Wed, 16 Nov 2022 13:00:00 GMT")));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("org.springframework:spring-core", "6.0.0", "maven");

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2022-11-16T13:00:00Z"));
        assertThat(result.get().isDeprecated()).isFalse();
    }

    @Test
    void shouldReturnEmptyForUnknownEcosystem() {
        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("somepkg", "1.0.0", "unknown-eco");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenNpmRegistryReturns500() {
        wireMock.stubFor(get(urlEqualTo("/badpkg"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withBody("Internal Server Error")));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("badpkg", "1.0.0", "npm");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenNpmMetadataIsMalformed() {
        wireMock.stubFor(get(urlEqualTo("/malformed"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ invalid-json }")));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("malformed", "1.0.0", "npm");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenNpmMetadataMissingTimeOrVersion() {
        wireMock.stubFor(get(urlEqualTo("/missing"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "versions": {
                                "1.0.0": {
                                  "name": "missing"
                                }
                              }
                            }
                            """)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("missing", "1.0.0", "npm");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenPypiRegistryReturns500() {
        wireMock.stubFor(get(urlEqualTo("/pypi/badpkg/json"))
                .willReturn(aResponse()
                        .withStatus(500)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("badpkg", "1.0.0", "pypi");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenPypiMetadataIsMalformed() {
        wireMock.stubFor(get(urlEqualTo("/pypi/malformed/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ invalid-json }")));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("malformed", "1.0.0", "pypi");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenPypiMetadataMissingReleases() {
        wireMock.stubFor(get(urlEqualTo("/pypi/missing/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "info": {}
                            }
                            """)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("missing", "1.0.0", "pypi");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenMavenRegistryReturns404() {
        wireMock.stubFor(head(urlEqualTo("/maven2/org/example/badpkg/1.0.0/"))
                .willReturn(aResponse()
                        .withStatus(404)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("org.example:badpkg", "1.0.0", "maven");
        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenMavenHeaderMissingLastModified() {
        wireMock.stubFor(head(urlEqualTo("/maven2/org/example/missing/1.0.0/"))
                .willReturn(aResponse()
                        .withStatus(200))); // OK but missing Last-Modified header

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("org.example:missing", "1.0.0", "maven");
        assertThat(result).isEmpty();
    }
}
