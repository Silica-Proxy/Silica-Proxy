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
import com.silicaproxy.model.dto.RegistryLookup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/** FOUND / NOT_FOUND / UNAVAILABLE statuses of the PyPI and Maven registry lookups. */
class RegistryClientLookupStatusTest extends BaseIntegrationTest {

    private static final String CENTRAL_DIR = "/maven2/com/example/lib/1.0.0/";
    private static final String INTERCEPTED_PATH = "/repository/maven-proxy/com/example/lib/1.0.0/lib-1.0.0.jar";

    private final RegistryClient registryClient;

    @Autowired
    RegistryClientLookupStatusTest(RegistryClient registryClient) {
        this.registryClient = registryClient;
    }

    @BeforeEach
    void resetWiremock() {
        wireMock.resetAll();
    }

    private static String pypiRelease(String version) {
        return "{\"releases\":{\"" + version + "\":[{\"filename\":\"lib-" + version + ".tar.gz\","
                + "\"upload_time_iso_8601\":\"2020-01-01T00:00:00Z\",\"yanked\":false}]}}";
    }

    private void stubPypi(int status, String body) {
        wireMock.stubFor(get(urlEqualTo("/pypi/lib/json")).willReturn(aResponse()
                .withStatus(status).withHeader("Content-Type", "application/json").withBody(body)));
    }

    private void stubHead(String path, int status) {
        wireMock.stubFor(head(urlEqualTo(path)).willReturn(aResponse()
                .withStatus(status).withHeader("Last-Modified", "Wed, 01 Jan 2020 00:00:00 GMT")));
    }

    @Test
    void pypiShouldBeFoundWhenReleaseHasFiles() {
        stubPypi(200, pypiRelease("1.0.0"));

        RegistryLookup lookup = registryClient.lookupPypi("lib", "1.0.0", "");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.FOUND);
        assertThat(lookup.metadata()).get().extracting(m -> m.publishedAt())
                .isEqualTo(Instant.parse("2020-01-01T00:00:00Z"));
    }

    @Test
    void pypiShouldBeNotFoundOn404() {
        stubPypi(404, "{}");

        assertThat(registryClient.lookupPypi("lib", "1.0.0", "").status()).isEqualTo(RegistryLookup.Status.NOT_FOUND);
    }

    @Test
    void pypiShouldBeNotFoundWhenVersionIsAbsent() {
        stubPypi(200, pypiRelease("1.0.0"));

        assertThat(registryClient.lookupPypi("lib", "2.0.0", "").status()).isEqualTo(RegistryLookup.Status.NOT_FOUND);
    }

    @Test
    void pypiShouldBeNotFoundWhenReleaseHasNoFile() {
        stubPypi(200, "{\"releases\":{\"1.0.0\":[]}}");

        assertThat(registryClient.lookupPypi("lib", "1.0.0", "").status()).isEqualTo(RegistryLookup.Status.NOT_FOUND);
    }

    @Test
    void pypiShouldBeUnavailableOnServerError() {
        stubPypi(500, "{}");

        assertThat(registryClient.lookupPypi("lib", "1.0.0", "").status()).isEqualTo(RegistryLookup.Status.UNAVAILABLE);
    }

    @Test
    void pypiShouldBeUnavailableWhenResponseHasNoReleasesField() {
        stubPypi(200, "{\"info\":{\"name\":\"lib\"}}");

        assertThat(registryClient.lookupPypi("lib", "1.0.0", "").status()).isEqualTo(RegistryLookup.Status.UNAVAILABLE);
    }

    @Test
    void mavenShouldBeFoundOnCentral() {
        stubHead(CENTRAL_DIR, 200);

        RegistryLookup lookup = registryClient.lookupMaven("com.example:lib", "1.0.0", "");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.FOUND);
        assertThat(lookup.metadata()).get().extracting(m -> m.publishedAt())
                .isEqualTo(Instant.parse("2020-01-01T00:00:00Z"));
    }

    @Test
    void mavenShouldBeNotFoundWhenCentralAnswers404WithoutInterceptedUrl() {
        stubHead(CENTRAL_DIR, 404);

        assertThat(registryClient.lookupMaven("com.example:lib", "1.0.0", "").status())
                .isEqualTo(RegistryLookup.Status.NOT_FOUND);
    }

    @Test
    void mavenShouldBeUnavailableWhenCentralFailsWithoutInterceptedUrl() {
        stubHead(CENTRAL_DIR, 503);

        assertThat(registryClient.lookupMaven("com.example:lib", "1.0.0", "").status())
                .isEqualTo(RegistryLookup.Status.UNAVAILABLE);
    }

    @Test
    void mavenShouldBeNotFoundWhenCentralAndInterceptedUrlBothAnswer404() {
        stubHead(CENTRAL_DIR, 404);
        stubHead(INTERCEPTED_PATH, 404);

        assertThat(registryClient.lookupMaven("com.example:lib", "1.0.0", wireMock.baseUrl() + INTERCEPTED_PATH).status())
                .isEqualTo(RegistryLookup.Status.NOT_FOUND);
    }

    @Test
    void mavenShouldBeUnavailableWhenCentralFailsAndInterceptedUrlAnswers404() {
        stubHead(CENTRAL_DIR, 503);
        stubHead(INTERCEPTED_PATH, 404);

        assertThat(registryClient.lookupMaven("com.example:lib", "1.0.0", wireMock.baseUrl() + INTERCEPTED_PATH).status())
                .isEqualTo(RegistryLookup.Status.UNAVAILABLE);
    }

    @Test
    void mavenShouldBeFoundThroughInterceptedUrlWhenCentralAnswers404() {
        stubHead(CENTRAL_DIR, 404);
        stubHead(INTERCEPTED_PATH, 200);

        assertThat(registryClient.lookupMaven("com.example:lib", "1.0.0", wireMock.baseUrl() + INTERCEPTED_PATH).status())
                .isEqualTo(RegistryLookup.Status.FOUND);
    }
}
