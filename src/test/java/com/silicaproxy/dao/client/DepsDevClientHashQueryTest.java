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
import com.silicaproxy.model.dto.HashLookup;
import com.silicaproxy.model.dto.HashType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * deps.dev query by file digest ({@code /v3/query?hash.type=…&hash.value=<base64>}). The deps-dev
 * URL is wired to WireMock at "<wiremock>/depsdev/v3/" by BaseIntegrationTest.
 */
@TestPropertySource(properties = "silicaproxy.api-fallback.deps-dev.enabled=true")
class DepsDevClientHashQueryTest extends BaseIntegrationTest {

    // SHA-1 of slf4j-api-2.0.9.jar as announced by Maven Central (X-Checksum-Sha1) ; its base64
    // form contains '/' and '=', which must reach deps.dev percent-encoded exactly once.
    private static final String SHA1 = "7cf2726fdcfbc8610f9a71fb3ed639871f315340";
    private static final String SHA1_BASE64 = "fPJyb9z7yGEPmnH7PtY5hx8xU0A=";
    private static final String QUERY_PATH = "/depsdev/v3/query";

    private final DepsDevClient depsDevClient;

    @Autowired
    DepsDevClientHashQueryTest(DepsDevClient depsDevClient) {
        this.depsDevClient = depsDevClient;
    }

    @BeforeEach
    void resetWiremock() {
        wireMock.resetAll();
    }

    private static String result(String system, String name, String version) {
        return "{\"version\":{\"versionKey\":{\"system\":\"" + system + "\",\"name\":\"" + name
                + "\",\"version\":\"" + version + "\"},\"publishedAt\":\"2023-09-03T16:14:32Z\"}}";
    }

    private void stubQuery(int status, String body) {
        wireMock.stubFor(get(urlPathEqualTo(QUERY_PATH)).willReturn(aResponse()
                .withStatus(status).withHeader("Content-Type", "application/json").withBody(body)));
    }

    @Test
    void shouldSendDigestTypeAndBase64Value() {
        stubQuery(200, "{\"results\":[" + result("MAVEN", "org.slf4j:slf4j-api", "2.0.9") + "]}");

        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA1, SHA1);

        assertThat(lookup.status()).isEqualTo(HashLookup.Status.FOUND);
        assertThat(lookup.ecosystem()).isEqualTo("maven");
        assertThat(lookup.packageName()).isEqualTo("org.slf4j:slf4j-api");
        assertThat(lookup.version()).isEqualTo("2.0.9");
        wireMock.verify(getRequestedFor(urlPathEqualTo(QUERY_PATH))
                .withQueryParam("hash.type", equalTo("SHA1"))
                .withQueryParam("hash.value", equalTo(SHA1_BASE64)));
    }

    @Test
    void shouldSendSha256Type() {
        stubQuery(200, "{\"results\":[" + result("PYPI", "six", "1.16.0") + "]}");

        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA256, "ab".repeat(32));

        assertThat(lookup.status()).isEqualTo(HashLookup.Status.FOUND);
        assertThat(lookup.ecosystem()).isEqualTo("pypi");
        wireMock.verify(getRequestedFor(urlPathEqualTo(QUERY_PATH)).withQueryParam("hash.type", equalTo("SHA256")));
    }

    @Test
    void shouldMapNpmSystem() {
        stubQuery(200, "{\"results\":[" + result("NPM", "@scope/lib", "1.0.0") + "]}");

        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA1, SHA1);

        assertThat(lookup.ecosystem()).isEqualTo("npm");
        assertThat(lookup.packageName()).isEqualTo("@scope/lib");
    }

    @Test
    void shouldIgnoreUnsupportedSystems() {
        stubQuery(200, "{\"results\":[" + result("GO", "example.com/lib", "v1.0.0") + "]}");

        assertThat(depsDevClient.queryByHash(HashType.SHA1, SHA1).status()).isEqualTo(HashLookup.Status.NOT_FOUND);
    }

    @Test
    void shouldKeepSupportedResultAmongUnsupportedOnes() {
        stubQuery(200, "{\"results\":[" + result("GO", "example.com/lib", "v1.0.0") + ","
                + result("MAVEN", "org.slf4j:slf4j-api", "2.0.9") + "]}");

        assertThat(depsDevClient.queryByHash(HashType.SHA1, SHA1).status()).isEqualTo(HashLookup.Status.FOUND);
    }

    @Test
    void shouldCollapseDuplicateResultsOfSameVersion() {
        stubQuery(200, "{\"results\":[" + result("MAVEN", "org.slf4j:slf4j-api", "2.0.9") + ","
                + result("MAVEN", "org.slf4j:slf4j-api", "2.0.9") + "]}");

        assertThat(depsDevClient.queryByHash(HashType.SHA1, SHA1).status()).isEqualTo(HashLookup.Status.FOUND);
    }

    @Test
    void shouldBeAmbiguousWhenSeveralVersionsShareTheDigest() {
        stubQuery(200, "{\"results\":[" + result("MAVEN", "org.example:lib", "1.0.0") + ","
                + result("MAVEN", "org.example:lib-shaded", "1.0.0") + "]}");

        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA1, SHA1);

        assertThat(lookup.status()).isEqualTo(HashLookup.Status.AMBIGUOUS);
        assertThat(lookup.packageName()).isEqualTo("unknown");
    }

    @Test
    void shouldBeNotFoundOn404() {
        wireMock.stubFor(get(urlPathEqualTo(QUERY_PATH)).willReturn(aResponse()
                .withStatus(404).withBody("no results match query")));

        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA1, SHA1);

        assertThat(lookup.status()).isEqualTo(HashLookup.Status.NOT_FOUND);
        assertThat(lookup.call().httpStatus()).isEqualTo(404);
        assertThat(lookup.call().isError()).isFalse();
    }

    @Test
    void shouldBeNotFoundOnEmptyResults() {
        stubQuery(200, "{\"results\":[]}");

        assertThat(depsDevClient.queryByHash(HashType.SHA1, SHA1).status()).isEqualTo(HashLookup.Status.NOT_FOUND);
    }

    @Test
    void shouldBeUnavailableOnServerError() {
        stubQuery(503, "{}");

        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA1, SHA1);

        assertThat(lookup.status()).isEqualTo(HashLookup.Status.UNAVAILABLE);
        assertThat(lookup.call().httpStatus()).isEqualTo(503);
        assertThat(lookup.call().isError()).isTrue();
    }
}
