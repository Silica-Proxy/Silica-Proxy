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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * PyPI lets maintainers add files to an existing release long after it was first published
 * (e.g. pyyaml 5.3.1 : first file 2020-03-18, cp39 wheels added 2020-11-19). The quarantine
 * publish date must be the one of the file actually downloaded, not the release's first file.
 */
class RegistryClientPypiFileDateTest extends BaseIntegrationTest {

    // files[0] is old ; the win_amd64 wheel was added to the same release much later.
    private static final String RELEASE_WITH_LATE_WHEEL = """
            {
              "releases": {
                "5.3.1": [
                  {"filename": "latepkg-5.3.1.tar.gz", "upload_time_iso_8601": "2020-03-18T21:00:00.000000Z"},
                  {"filename": "latepkg-5.3.1-cp38-cp38-win_amd64.whl", "upload_time_iso_8601": "2020-03-19T10:00:00.000000Z"},
                  {"filename": "latepkg-5.3.1-cp39-cp39-win_amd64.whl", "upload_time_iso_8601": "2020-11-19T17:00:00.000000Z"}
                ]
              }
            }
            """;

    private final RegistryClient registryClient;

    @Autowired
    RegistryClientPypiFileDateTest(RegistryClient registryClient) {
        this.registryClient = registryClient;
    }

    @BeforeEach
    void resetWiremock() {
        wireMock.resetAll();
        wireMock.stubFor(get(urlEqualTo("/pypi/latepkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(RELEASE_WITH_LATE_WHEEL)));
    }

    @Test
    void shouldUseUploadTimeOfTheRequestedFileRatherThanTheFirstFile() {
        String fullUrl = "https://files.pythonhosted.org/packages/ab/cd/latepkg-5.3.1-cp39-cp39-win_amd64.whl";

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("latepkg", "5.3.1", "pypi", fullUrl);

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2020-11-19T17:00:00Z"));
    }

    @Test
    void shouldUseUploadTimeOfAnOlderRequestedFile() {
        String fullUrl = "https://files.pythonhosted.org/packages/ab/cd/latepkg-5.3.1-cp38-cp38-win_amd64.whl";

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("latepkg", "5.3.1", "pypi", fullUrl);

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2020-03-19T10:00:00Z"));
    }

    @Test
    void shouldMatchAPercentEncodedRequestedFilename() {
        wireMock.stubFor(get(urlEqualTo("/pypi/encpkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {"releases": {"1.0": [
                              {"filename": "encpkg-1.0.tar.gz", "upload_time_iso_8601": "2019-01-01T00:00:00Z"},
                              {"filename": "encpkg-1.0+local-py3-none-any.whl", "upload_time_iso_8601": "2019-06-01T00:00:00Z"}
                            ]}}
                            """)));
        String fullUrl = "https://files.pythonhosted.org/packages/ab/encpkg-1.0%2Blocal-py3-none-any.whl";

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("encpkg", "1.0", "pypi", fullUrl);

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2019-06-01T00:00:00Z"));
    }

    @Test
    void shouldFallBackToLatestUploadWhenRequestedFileIsNotListed() {
        String fullUrl = "https://files.pythonhosted.org/packages/ab/cd/latepkg-5.3.1-cp312-cp312-win_amd64.whl";

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("latepkg", "5.3.1", "pypi", fullUrl);

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2020-11-19T17:00:00Z"));
    }

    @Test
    void shouldFallBackToLatestUploadWhenNoUrlIsKnown() {
        Optional<PackageMetadataResult> result = registryClient.fetchMetadata("latepkg", "5.3.1", "pypi");

        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2020-11-19T17:00:00Z"));
    }

    @Test
    void shouldSkipFilesWithoutParsableUploadTime() {
        wireMock.stubFor(get(urlEqualTo("/pypi/partialpkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {"releases": {"2.0": [
                              {"filename": "partialpkg-2.0.tar.gz", "upload_time": "2021-02-03T04:05:06"},
                              {"filename": "partialpkg-2.0-py3-none-any.whl", "upload_time_iso_8601": "not-a-date"},
                              {"filename": "partialpkg-2.0-py2-none-any.whl"}
                            ]}}
                            """)));

        Optional<PackageMetadataResult> result = registryClient.fetchMetadata(
                "partialpkg", "2.0", "pypi", "https://files.pythonhosted.org/packages/x/partialpkg-2.0-py3-none-any.whl");

        // The requested wheel has no usable time : the release's latest usable upload is used.
        assertThat(result).isPresent();
        assertThat(result.get().publishedAt()).isEqualTo(Instant.parse("2021-02-03T04:05:06Z"));
    }

    @Test
    void shouldReturnEmptyWhenNoFileHasAnUploadTime() {
        wireMock.stubFor(get(urlEqualTo("/pypi/notimepkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {"releases": {"1.0": [{"filename": "notimepkg-1.0.tar.gz"}]}}
                            """)));

        assertThat(registryClient.fetchMetadata("notimepkg", "1.0", "pypi")).isEmpty();
    }
}
