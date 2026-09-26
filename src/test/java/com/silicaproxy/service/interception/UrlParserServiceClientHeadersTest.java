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
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PyPI and Maven clients recognised from their headers on hosts and layouts the URL parser does
 * not know : a PyPI client's sdist is identified, any other request is only tagged.
 */
class UrlParserServiceClientHeadersTest {

    private static final String UNKNOWN_LAYOUT_SDIST = "https://files.corp.example/dist/requests-2.31.0.tar.gz";

    private final UrlParserService urlParserService = new UrlParserService();

    private static HttpHeaders userAgent(String value) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.USER_AGENT, value);
        return headers;
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "pip/24.0 {\"ci\":null,\"cpu\":\"arm64\",\"implementation\":{\"name\":\"CPython\"}}",
        "uv/0.4.18 {\"installer\":{\"name\":\"uv\",\"version\":\"0.4.18\"}}",
        "poetry/1.8.3",
        "PIP/24.0"
    })
    void shouldIdentifySdistRequestedByPypiClient(String agent) {
        assertThat(urlParserService.detectClientEcosystem(UNKNOWN_LAYOUT_SDIST, userAgent(agent)))
                .contains(new ParsedPackage("requests", "2.31.0", "pypi"));
    }

    @Test
    void shouldIdentifySdistFromPep691Accept() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, "application/vnd.pypi.simple.v1+json, text/html;q=0.01");

        assertThat(urlParserService.detectClientEcosystem(UNKNOWN_LAYOUT_SDIST, headers))
                .contains(new ParsedPackage("requests", "2.31.0", "pypi"));
    }

    @Test
    void shouldTagPypiIndexRequestWithoutVersion() {
        assertThat(urlParserService.detectClientEcosystem("https://mirror.corp.example/simple/requests/", userAgent("pip/24.0")))
                .contains(ParsedPackage.unknown("pypi"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Apache-Maven/3.9.6 (Java 21.0.2; Mac OS X 14.4)",
        "Gradle/8.5 (Mac OS X;14.4;aarch64) (Eclipse Adoptium;21.0.2;21.0.2+13-LTS)"
    })
    void shouldTagMavenClientTrafficWithoutVersion(String agent) {
        assertThat(urlParserService.detectClientEcosystem(
                "https://repo.corp.example/libs/com/acme/lib/maven-metadata.xml", userAgent(agent)))
                .contains(ParsedPackage.unknown("maven"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"curl/8.4.0", "Artifactory/7.77.5", "Nexus/3.68.1-02 (OSS; Linux)"})
    void shouldIgnoreOtherClients(String agent) {
        assertThat(urlParserService.detectClientEcosystem(UNKNOWN_LAYOUT_SDIST, userAgent(agent))).isEmpty();
    }

    @Test
    void shouldIgnoreRequestWithoutClientHeaders() {
        assertThat(urlParserService.detectClientEcosystem(UNKNOWN_LAYOUT_SDIST, new HttpHeaders())).isEmpty();
    }
}
