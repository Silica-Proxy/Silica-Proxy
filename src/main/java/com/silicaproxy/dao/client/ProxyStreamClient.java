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

import org.jspecify.annotations.NullMarked;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import io.micrometer.core.annotation.Timed;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * Relays the download of a package binary (jar/tgz/whl) in strict streaming
 * (without loading the file in memory), propagating authorization headers received
 * from the artifacts repository. Called by {@code ProxyController} only after an ALLOW/WHITELIST 
 * verdict, to forward the public registry response directly to the calling client.
 */
@Component
@NullMarked
public class ProxyStreamClient {

    private final ClientHttpRequestFactory requestFactory;
    private final com.silicaproxy.config.SsrfValidator ssrfValidator;

    public ProxyStreamClient(
            @Qualifier("registriesRequestFactory") ClientHttpRequestFactory registriesRequestFactory,
            com.silicaproxy.config.SsrfValidator ssrfValidator) {
        this.ssrfValidator = ssrfValidator;
        this.requestFactory = registriesRequestFactory;
    }

    @Timed(value = "silicaproxy.dao.proxystream.streamcontent",
            description = "Duration of streaming binary content from remote registry",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public StreamResponse streamContent(String url, HttpHeaders headers) throws IOException {
        ssrfValidator.validateUrl(url);
        ClientHttpRequest request = requestFactory.createRequest(URI.create(url), HttpMethod.GET);
        
        // Forward headers safely
        headers.forEach((headerName, headerValues) -> {
            if (!headerName.equalsIgnoreCase("Host") 
                    && !headerName.equalsIgnoreCase("Connection")
                    && !headerName.toLowerCase().startsWith("x-forwarded-")
                    && !headerName.equalsIgnoreCase("x-real-ip")) {
                request.getHeaders().addAll(headerName, headerValues);
            }
        });

        ClientHttpResponse response = request.execute();
        return new StreamResponse(
                (HttpStatus) response.getStatusCode(),
                response.getHeaders(),
                response.getBody()
        );
    }

    public record StreamResponse(
            HttpStatus status,
            HttpHeaders headers,
            InputStream body
    ) {
        public StreamResponse {
            headers = HttpHeaders.readOnlyHttpHeaders(headers);
        }
    }
}
