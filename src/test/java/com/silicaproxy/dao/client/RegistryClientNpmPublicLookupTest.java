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
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link RegistryClient#lookupNpmPublic} must tell "the public registry does not know this
 * version" (fallback to the origin registry allowed) apart from "the public registry could not
 * answer" (no fallback).
 */
class RegistryClientNpmPublicLookupTest extends BaseIntegrationTest {

    private final RegistryClient registryClient;

    @Autowired
    RegistryClientNpmPublicLookupTest(RegistryClient registryClient) {
        this.registryClient = registryClient;
    }

    @BeforeEach
    void resetWiremock() {
        wireMock.resetAll();
    }

    @Test
    void shouldReturnFoundWithPublishDate() {
        wireMock.stubFor(get(urlEqualTo("/lookup-found"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {"time": {"1.0.0": "2021-05-02T12:00:00.000Z"},
                             "versions": {"1.0.0": {"name": "lookup-found", "version": "1.0.0"}}}
                            """)));

        RegistryLookup lookup = registryClient.lookupNpmPublic("lookup-found", "1.0.0");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.FOUND);
        assertThat(lookup.metadata()).isPresent();
        assertThat(lookup.metadata().get().publishedAt()).isEqualTo(Instant.parse("2021-05-02T12:00:00Z"));
    }

    @Test
    void shouldReturnNotFoundOn404() {
        wireMock.stubFor(get(urlEqualTo("/lookup-missing")).willReturn(aResponse().withStatus(404)));

        RegistryLookup lookup = registryClient.lookupNpmPublic("lookup-missing", "1.0.0");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.NOT_FOUND);
        assertThat(lookup.metadata()).isEmpty();
    }

    @Test
    void shouldReturnNotFoundWhenVersionIsUnknownToThePublicRegistry() {
        wireMock.stubFor(get(urlEqualTo("/lookup-other-version"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"1.0.0\": \"2020-01-01T00:00:00Z\"}, \"versions\": {}}")));

        RegistryLookup lookup = registryClient.lookupNpmPublic("lookup-other-version", "2.0.0");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.NOT_FOUND);
    }

    @Test
    void shouldReturnUnavailableOnServerError() {
        wireMock.stubFor(get(urlEqualTo("/lookup-down")).willReturn(aResponse().withStatus(503)));

        RegistryLookup lookup = registryClient.lookupNpmPublic("lookup-down", "1.0.0");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.UNAVAILABLE);
        assertThat(lookup.metadata()).isEmpty();
    }

    @Test
    void shouldReturnUnavailableOnMalformedBody() {
        wireMock.stubFor(get(urlEqualTo("/lookup-malformed"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ invalid-json }")));

        RegistryLookup lookup = registryClient.lookupNpmPublic("lookup-malformed", "1.0.0");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.UNAVAILABLE);
    }

    @Test
    void shouldReturnUnavailableOnConnectionFailure() {
        wireMock.stubFor(get(urlEqualTo("/lookup-reset"))
                .willReturn(aResponse().withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER)));

        RegistryLookup lookup = registryClient.lookupNpmPublic("lookup-reset", "1.0.0");

        assertThat(lookup.status()).isEqualTo(RegistryLookup.Status.UNAVAILABLE);
    }
}
