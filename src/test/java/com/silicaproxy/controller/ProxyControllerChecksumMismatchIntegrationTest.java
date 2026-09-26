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
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.HashType;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.ExpectedDigest;
import com.silicaproxy.service.interception.ParsedPackage;
import com.silicaproxy.service.interception.ResponseIdentificationService;
import com.silicaproxy.service.interception.ResponseIdentificationService.ResponseIdentification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Through the real servlet container : when the body of a download identified from its announced
 * digest does not match it, the client gets a failed download, never a complete-looking file.
 */
class ProxyControllerChecksumMismatchIntegrationTest extends BaseIntegrationTest {

    private static final String URL = "http://repo.corp.example/api/download/blob/4f2a91";

    @LocalServerPort
    private int port;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @MockitoBean
    private ResponseIdentificationService responseIdentification;

    @MockitoBean
    private SecurityService securityService;

    private RestClient proxyRestClient;

    @BeforeEach
    void setUp() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        proxyRestClient = RestClient.builder().requestFactory(factory).build();
        when(securityService.getDecision(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule)."));
        when(responseIdentification.isEnabled()).thenReturn(true);
    }

    private static byte[] body(int size) {
        byte[] body = new byte[size];
        new Random(3).nextBytes(body);
        return body;
    }

    private void upstreamServes(byte[] body, byte[] announcedFile, boolean withContentLength) throws Exception {
        ExpectedDigest announced = new ExpectedDigest(HashType.SHA1,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(announcedFile)));
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Checksum-Sha1", announced.hex());
        if (withContentLength) {
            headers.setContentLength(body.length);
        }
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, headers, new ByteArrayInputStream(body)));
        when(responseIdentification.identify(any(), any())).thenReturn(Optional.of(new ResponseIdentification(
                new ParsedPackage("org.example:lib", "1.0.0", "maven"), announced)));
    }

    private byte[] download() {
        return proxyRestClient.get().uri(URL).retrieve().body(byte[].class);
    }

    @Test
    void shouldRelayMatchingBody() throws Exception {
        byte[] body = body(200_000);
        upstreamServes(body, body, true);

        assertThat(download()).isEqualTo(body);
    }

    @Test
    void shouldFailDownloadWithContentLengthWhenBodyDoesNotMatch() throws Exception {
        upstreamServes(body(200_000), "harmless".getBytes(), true);

        assertThatThrownBy(this::download).isInstanceOf(RestClientException.class);
    }

    @Test
    void shouldFailChunkedDownloadWhenBodyDoesNotMatch() throws Exception {
        upstreamServes(body(200_000), "harmless".getBytes(), false);

        assertThatThrownBy(this::download).isInstanceOf(RestClientException.class);
    }
}
