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

package com.silicaproxy.controller;

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.client.RestClient;

import java.net.InetSocketAddress;
import java.net.Proxy;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Through the real proxy, with the upstream registry rate-limiting it (429) : the artifacts
 * repository gets a 429 with Retry-After, the registry is no longer called while suspended, and a
 * package whose publish date could not be checked is never let through.
 */
class UpstreamThrottleIntegrationTest extends BaseIntegrationTest {

    private static final String METADATA = "/maven2/org/slf4j/slf4j-api/maven-metadata.xml";
    private static final String POM = "/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.pom";
    private static final String VERSION_DIR = "/maven2/org/slf4j/slf4j-api/2.0.13/";

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    private RestClient proxyRestClient;

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        proxyRestClient = RestClient.builder().requestFactory(factory).build();
    }

    private ResponseEntity<String> download(String path) {
        return proxyRestClient.get().uri("http://localhost:" + wireMock.port() + path)
                .retrieve()
                .onStatus(status -> true, (request, response) -> { })
                .toEntity(String.class);
    }

    @Test
    void shouldStopCallingTheRegistryOnceItAnswered429() {
        wireMock.stubFor(get(urlEqualTo(METADATA)).willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        ResponseEntity<String> first = download(METADATA);
        ResponseEntity<String> second = download(METADATA);
        ResponseEntity<String> artifact = download(POM);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(Long.parseLong(second.getHeaders().getFirst(HttpHeaders.RETRY_AFTER))).isBetween(55L, 75L);
        // The artifact needs a publish date the suspended registry cannot give : blocked, not let through.
        assertThat(artifact.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(artifact.getBody()).contains("UPSTREAM_THROTTLED");
        wireMock.verify(1, anyRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotLetAnArtifactThroughWhenThePublishDateLookupIsRateLimited() {
        wireMock.stubFor(head(urlEqualTo(VERSION_DIR)).willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));
        wireMock.stubFor(get(urlEqualTo(POM)).willReturn(aResponse().withStatus(200).withBody("<project/>")));

        ResponseEntity<String> response = download(POM);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isNotBlank();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getBody()).contains("UPSTREAM_THROTTLED");
        wireMock.verify(0, getRequestedFor(urlEqualTo(POM)));
        assertThat(jdbcClient.sql("SELECT COUNT(*) FROM api_cache").query(Long.class).single()).isZero();
    }
}
