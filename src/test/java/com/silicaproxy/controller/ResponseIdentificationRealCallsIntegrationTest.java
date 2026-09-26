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

import com.silicaproxy.dao.client.DepsDevClient;
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.HashLookup;
import com.silicaproxy.model.dto.HashType;
import com.silicaproxy.service.decision.SecurityService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Identification from the upstream response against the real deps.dev API, with the real
 * slf4j-api-2.0.9.jar and the SHA-1 Maven Central announces for it (X-Checksum-Sha1). The upstream
 * is served under an opaque URL, so only the response can identify the package. DepsDevClient is
 * a spy : its calls are real, only counted.
 *
 * Does not extend BaseIntegrationTest to avoid substituting the deps.dev URL with WireMock.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ResponseIdentificationRealCallsIntegrationTest {

    private static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine");
    private static final String JAR_URL =
            "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar";
    private static final String OPAQUE_URL = "http://repo.corp.example/api/download/blob/4f2a91";

    private static byte[] jar = new byte[0];
    private static String announcedSha1 = "";

    static {
        postgres.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("silicaproxy.security.ssrf-protection.enabled", () -> "false");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-path", () -> "");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-password", () -> "");
        registry.add("silicaproxy.proxy.port", () -> 0);
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "true");
        registry.add("silicaproxy.api-fallback.deps-dev.url", () -> "https://api.deps.dev/v3/");
        registry.add("silicaproxy.response-identification.enabled", () -> "true");
    }

    @LocalServerPort
    private int port;

    @MockitoSpyBean
    private DepsDevClient depsDevClient;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @MockitoBean
    private SecurityService securityService;

    private RestClient proxyRestClient;

    @BeforeAll
    static void downloadRealJar() throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpResponse<byte[]> response = client.send(HttpRequest.newBuilder(URI.create(JAR_URL)).build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            jar = response.body();
            announcedSha1 = response.headers().firstValue("X-Checksum-Sha1").orElseThrow();
        }
        assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(jar))).isEqualTo(announcedSha1);
    }

    @BeforeEach
    void setUp() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        proxyRestClient = RestClient.builder().requestFactory(factory).build();
        jdbcClient.sql("TRUNCATE file_digest_index").update();
    }

    private void upstreamServes(byte[] body, String sha1Header) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/java-archive");
        headers.set("X-Checksum-Sha1", sha1Header);
        headers.setContentLength(body.length);
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, headers, new ByteArrayInputStream(body)));
    }

    @Test
    void depsDevShouldIdentifyRealJarFromItsSha1() {
        HashLookup lookup = depsDevClient.queryByHash(HashType.SHA1, announcedSha1);

        assertThat(lookup.status()).isEqualTo(HashLookup.Status.FOUND);
        assertThat(lookup.ecosystem()).isEqualTo("maven");
        assertThat(lookup.packageName()).isEqualTo("org.slf4j:slf4j-api");
        assertThat(lookup.version()).isEqualTo("2.0.9");
    }

    @Test
    void depsDevShouldNotFindUnknownDigest() {
        assertThat(depsDevClient.queryByHash(HashType.SHA1, "0".repeat(40)).status())
                .isEqualTo(HashLookup.Status.NOT_FOUND);
    }

    @Test
    void shouldBlockRealJarServedUnderOpaqueUrl() throws Exception {
        upstreamServes(jar, announcedSha1);
        when(securityService.getDecision(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new DecisionResult("COMPANY_POLICY", "BLACKLIST", "Blacklisted for the test."));

        assertThatThrownBy(() -> proxyRestClient.get().uri(OPAQUE_URL).retrieve().toEntity(byte[].class))
                .isInstanceOfSatisfying(HttpClientErrorException.class, e -> {
                    assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(e.getResponseBodyAsString()).contains("org.slf4j:slf4j-api").contains("2.0.9");
                });
        verify(securityService).getDecision(eq("org.slf4j:slf4j-api"), eq("2.0.9"), eq("maven"), anyString());
    }

    @Test
    void shouldRelayRealJarServedUnderOpaqueUrlWhenAllowed() throws Exception {
        upstreamServes(jar, announcedSha1);
        when(securityService.getDecision(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule)."));

        byte[] relayed = proxyRestClient.get().uri(OPAQUE_URL).retrieve().body(byte[].class);

        assertThat(relayed).isEqualTo(jar);
        verify(securityService).getDecision(eq("org.slf4j:slf4j-api"), eq("2.0.9"), eq("maven"), anyString());
    }

    @Test
    void shouldStoreIdentifiedDigestAndNotAskDepsDevAgain() throws Exception {
        when(securityService.getDecision(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule)."));

        upstreamServes(jar, announcedSha1);
        assertThat(proxyRestClient.get().uri(OPAQUE_URL).retrieve().body(byte[].class)).isEqualTo(jar);
        upstreamServes(jar, announcedSha1);
        assertThat(proxyRestClient.get().uri(OPAQUE_URL).retrieve().body(byte[].class)).isEqualTo(jar);

        verify(depsDevClient, times(1)).queryByHash(HashType.SHA1, announcedSha1);
        verify(securityService, times(2)).getDecision(eq("org.slf4j:slf4j-api"), eq("2.0.9"), eq("maven"), anyString());
        assertThat(jdbcClient.sql("SELECT hash_type, ecosystem, package_name, package_version "
                        + "FROM file_digest_index WHERE digest = ?")
                .param(announcedSha1)
                .query((rs, rowNum) -> rs.getString(1) + "|" + rs.getString(2) + "|" + rs.getString(3) + "|" + rs.getString(4))
                .list())
                .containsExactly("SHA1|maven|org.slf4j:slf4j-api|2.0.9");
    }
}
