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
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import io.micrometer.core.annotation.Timed;

import java.util.Locale;
import java.util.Optional;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Relays the download of a package binary (jar/tgz/whl) in strict streaming
 * (without loading the file in memory), propagating authorization headers received
 * from the artifacts repository. Called by {@code ProxyController} only after an ALLOW 
 * verdict, to forward the public registry response directly to the calling client. A host that
 * answered 429 is not called again before its suspension ends ({@link UpstreamThrottle}) : the
 * client gets a 429 with the remaining {@code Retry-After} instead, so its retries no longer
 * extend the registry's rate limit.
 */
@Component
@NullMarked
public class ProxyStreamClient {

    private final ClientHttpRequestFactory requestFactory;
    private final com.silicaproxy.config.SsrfValidator ssrfValidator;
    private final UpstreamThrottle upstreamThrottle;

    public ProxyStreamClient(
            @Qualifier("registriesRequestFactory") ClientHttpRequestFactory registriesRequestFactory,
            com.silicaproxy.config.SsrfValidator ssrfValidator,
            UpstreamThrottle upstreamThrottle) {
        this.ssrfValidator = ssrfValidator;
        this.requestFactory = registriesRequestFactory;
        this.upstreamThrottle = upstreamThrottle;
    }

    @Timed(value = "silicaproxy.dao.proxystream.streamcontent",
            description = "Duration of streaming binary content from remote registry",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public StreamResponse streamContent(String url, HttpHeaders headers) throws IOException {
        ssrfValidator.validateUrl(url);
        URI uri = URI.create(url);
        Optional<Instant> suspendedUntil = upstreamThrottle.suspendedUntil(uri);
        if (suspendedUntil.isPresent()) {
            upstreamThrottle.recordSkipped(uri, UpstreamThrottle.Origin.RELAY);
            return suspended(suspendedUntil.get());
        }
        ClientHttpRequest request = requestFactory.createRequest(uri, HttpMethod.GET);
        
        // Forward headers safely
        headers.forEach((headerName, headerValues) -> {
            if (!headerName.equalsIgnoreCase("Host") 
                    && !headerName.equalsIgnoreCase("Connection")
                    && !headerName.toLowerCase(Locale.ROOT).startsWith("x-forwarded-")
                    && !headerName.equalsIgnoreCase("x-real-ip")
                    // Hop-by-hop, meant for this proxy : the client's proxy credential must never
                    // reach the registry (RFC 9110 11.7.2)
                    && !headerName.equalsIgnoreCase(HttpHeaders.PROXY_AUTHORIZATION)
                    && !headerName.equalsIgnoreCase("Proxy-Connection")
                    // Client identity meant for this proxy only (audit log), never for the registry
                    && !headerName.toLowerCase(Locale.ROOT).startsWith("x-silica-")) {
                request.getHeaders().addAll(headerName, headerValues);
            }
        });

        ClientHttpResponse response = request.execute();
        if (response.getStatusCode().value() == HttpStatus.TOO_MANY_REQUESTS.value()) {
            upstreamThrottle.recordThrottled(uri, response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER),
                    UpstreamThrottle.Origin.RELAY);
        } else if (response.getStatusCode().is2xxSuccessful()) {
            upstreamThrottle.recordSuccess(uri);
        }
        return new StreamResponse(
                (HttpStatus) response.getStatusCode(),
                response.getHeaders(),
                response.getBody(),
                response
        );
    }

    // What the host would most likely answer : a 429, with the time left before it may be asked again.
    private StreamResponse suspended(Instant until) {
        long retryAfter = upstreamThrottle.retryAfterSeconds(until);
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, Long.toString(retryAfter));
        headers.setCacheControl("no-store");
        headers.set(HttpHeaders.CONTENT_TYPE, "text/plain;charset=UTF-8");
        byte[] body = ("The upstream registry is rate-limiting the proxy, retry in " + retryAfter + " seconds.\n")
                .getBytes(StandardCharsets.UTF_8);
        headers.setContentLength(body.length);
        return new StreamResponse(HttpStatus.TOO_MANY_REQUESTS, headers, new ByteArrayInputStream(body));
    }

    /**
     * {@code underlyingResponse} is only used to release the connection on {@link #close()} --
     * closing just the {@code body} InputStream is not guaranteed by {@link ClientHttpResponse}'s
     * contract to free everything the response holds (e.g. HTTP/2 stream bookkeeping). Callers
     * that don't have a real response to release (tests constructing a fake stream) can use the
     * 3-arg constructor, which makes {@link #close()} a no-op.
     */
    public record StreamResponse(
            HttpStatus status,
            HttpHeaders headers,
            InputStream body,
            @Nullable Closeable underlyingResponse
    ) implements Closeable {
        public StreamResponse {
            headers = HttpHeaders.readOnlyHttpHeaders(headers);
        }

        public StreamResponse(HttpStatus status, HttpHeaders headers, InputStream body) {
            this(status, headers, body, null);
        }

        @Override
        public void close() throws IOException {
            if (underlyingResponse != null) {
                underlyingResponse.close();
            }
        }
    }
}
