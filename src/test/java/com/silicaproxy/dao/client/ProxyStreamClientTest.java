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

import com.silicaproxy.config.SsrfValidator;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProxyStreamClientTest {

    @Test
    void shouldCloseUnderlyingResponseWhenStreamResponseIsClosed() throws Exception {
        ClientHttpRequestFactory requestFactory = mock(ClientHttpRequestFactory.class);
        ClientHttpRequest request = mock(ClientHttpRequest.class);
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        SsrfValidator ssrfValidator = mock(SsrfValidator.class);

        when(requestFactory.createRequest(any(URI.class), any(HttpMethod.class))).thenReturn(request);
        when(request.getHeaders()).thenReturn(new HttpHeaders());
        when(request.execute()).thenReturn(response);
        when(response.getStatusCode()).thenReturn(HttpStatusCode.valueOf(200));
        when(response.getHeaders()).thenReturn(new HttpHeaders());
        InputStream body = new ByteArrayInputStream("content".getBytes());
        when(response.getBody()).thenReturn(body);

        ProxyStreamClient client = new ProxyStreamClient(requestFactory, ssrfValidator);

        // Before the fix, nothing ever called response.close() : ProxyController only reads
        // streamResponse.body() via StreamUtils.copy(), which never releases the underlying
        // ClientHttpResponse/connection, leaking one per proxied request.
        try (ProxyStreamClient.StreamResponse streamResponse =
                client.streamContent("https://registry.npmjs.org/lodash", new HttpHeaders())) {
            assertThat(streamResponse.status()).isEqualTo(HttpStatus.OK);
            assertThat(streamResponse.body()).isSameAs(body);
        }

        verify(response).close();
        verify(ssrfValidator).validateUrl("https://registry.npmjs.org/lodash");
    }

    @Test
    void shouldNotThrowWhenClosingAResponseBuiltWithoutAnUnderlyingResponse() throws Exception {
        // Simulates a caller (e.g. a test double elsewhere) with no real ClientHttpResponse to
        // release -- the 3-arg constructor must make close() a safe no-op.
        try (ProxyStreamClient.StreamResponse streamResponse = new ProxyStreamClient.StreamResponse(
                HttpStatus.OK, new HttpHeaders(), new ByteArrayInputStream(new byte[0]))) {
            assertThat(streamResponse.status()).isEqualTo(HttpStatus.OK);
        }
    }
}
