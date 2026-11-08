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

import com.silicaproxy.config.SsrfInterceptor;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.interception.HttpsUpgradePolicy;
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@NullMarked
public class ExternalValidationClient {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalValidationClient.class);

    private final HttpClient httpClient;
    private final SsrfInterceptor ssrfInterceptor;
    private final HttpsUpgradePolicy httpsUpgradePolicy;
    private final ObjectMapper objectMapper;
    // ASYNC triggers only wait for the acknowledgment : global external-validation-read-timeout-seconds
    private final RestClient asyncRestClient;
    // SYNC calls wait for the verdict : one client per distinct services.<name>.timeout-seconds,
    // all sharing the same HttpClient (and so the same connection pool / corporate proxy)
    private final Map<Integer, RestClient> syncRestClients = new ConcurrentHashMap<>();

    public ExternalValidationClient(
            @Qualifier("externalValidationHttpClient") HttpClient httpClient,
            SsrfInterceptor ssrfInterceptor,
            HttpsUpgradePolicy httpsUpgradePolicy,
            SilicaProxyProperties properties,
            ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.ssrfInterceptor = ssrfInterceptor;
        this.httpsUpgradePolicy = httpsUpgradePolicy;
        this.asyncRestClient = buildRestClient(properties.httpClient().externalValidationReadTimeoutSeconds());
    }

    // The service downloads the artifact itself : it gets the URL the relay fetches, upgraded to https
    // like the relay (a client such as Nexus asks in plain HTTP, the upstream answers 403 to it).
    private void putArtifactUrl(Map<String, Object> body, String fullUrl) {
        if (!fullUrl.isBlank()) {
            body.put("url", httpsUpgradePolicy.upgrade(fullUrl));
        }
    }

    // Sync call: POST and wait for {verdict, reason} response body, at most timeoutSeconds.
    // Returns verdict string ("ALLOWED"/"BLOCKED") or null on error.
    @Nullable
    @Timed(value = "silicaproxy.dao.extvalidation.client.callsync",
            description = "Duration of a synchronous call to an external validation service",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public ExternalValidationResult callSync(
            String url, @Nullable String apiKey, int timeoutSeconds,
            String packageName, String version, String ecosystem, String fullUrl) {
        Map<String, Object> body = new HashMap<>();
        body.put("packageName", packageName);
        body.put("version", version);
        body.put("ecosystem", ecosystem);
        putArtifactUrl(body, fullUrl);

        long start = System.nanoTime();
        try {
            RestClient restClient = syncRestClients.computeIfAbsent(timeoutSeconds, this::buildRestClient);
            @SuppressWarnings("unchecked")
            Map<String, Object> response = buildRequest(restClient, url, apiKey, body)
                    .retrieve()
                    .body(Map.class);

            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            if (LOG.isDebugEnabled()) {
                LOG.debug("External validation sync call to {} completed in {}ms", url, elapsedMs);
                LOG.debug("External validation sync call response from {}: {}", url, response);
            }

            if (response == null) {
                return null;
            }
            Object verdict = response.get("verdict");
            Object reason = response.get("reason");
            return new ExternalValidationResult(
                    verdict != null ? verdict.toString() : null,
                    reason != null ? reason.toString() : null);
        } catch (HttpStatusCodeException e) {
            LOG.warn("HTTP failure {} from external validation service at {}: {}",
                    e.getStatusCode().value(), url, e.getMessage());
            return null;
        } catch (Exception e) {
            LOG.warn("External validation sync call failed for {}/{} ({}): {}",
                    ecosystem, packageName, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("External validation sync call error details", e);
            }
            return null;
        }
    }

    // Async call: POST with callbackUrl. Not acknowledged (non-2xx, error, timeout) : sent=false.
    // Acknowledged : the service calls back later with the verdict -- unless it already knows the
    // package and puts the verdict in the response body ({"verdict":"ALLOWED|BLOCKED","reason":...}),
    // returned as immediateVerdict. A body without a usable verdict (empty, not JSON, PENDING) is a
    // plain acknowledgment.
    @Timed(value = "silicaproxy.dao.extvalidation.client.callasync",
            description = "Duration of triggering an asynchronous external validation",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public AsyncTriggerResult callAsync(
            String url, @Nullable String apiKey,
            String packageName, String version, String ecosystem, String callbackUrl,
            String fullUrl) {
        Map<String, Object> body = new HashMap<>();
        body.put("packageName", packageName);
        body.put("version", version);
        body.put("ecosystem", ecosystem);
        body.put("callbackUrl", callbackUrl);
        putArtifactUrl(body, fullUrl);

        String responseBody;
        try {
            responseBody = buildRequest(asyncRestClient, url, apiKey, body)
                    .retrieve()
                    .body(String.class);
        } catch (HttpStatusCodeException e) {
            LOG.warn("HTTP failure {} from external validation async service at {}: {}",
                    e.getStatusCode().value(), url, e.getMessage());
            return AsyncTriggerResult.NOT_SENT;
        } catch (Exception e) {
            LOG.warn("External validation async call failed for {}/{} ({}): {}",
                    ecosystem, packageName, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("External validation async call error details", e);
            }
            return AsyncTriggerResult.NOT_SENT;
        }
        return new AsyncTriggerResult(true, immediateVerdict(url, responseBody));
    }

    private @Nullable ExternalValidationResult immediateVerdict(String url, @Nullable String responseBody) {
        if (responseBody == null || responseBody.isBlank()) {
            return null;
        }
        try {
            JsonNode json = objectMapper.readTree(responseBody);
            JsonNode verdict = json.get("verdict");
            if (verdict == null || !verdict.isString()) {
                return null;
            }
            String value = verdict.asString();
            if (!"ALLOWED".equalsIgnoreCase(value) && !"BLOCKED".equalsIgnoreCase(value)) {
                return null;
            }
            JsonNode reason = json.get("reason");
            return new ExternalValidationResult(value,
                    reason != null && reason.isString() ? reason.asString() : null);
        } catch (Exception e) {
            LOG.debug("External validation async service at {} acknowledged with a body that is not a "
                    + "verdict: {}", url, e.getMessage());
            return null;
        }
    }

    private RestClient buildRestClient(int readTimeoutSeconds) {
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(readTimeoutSeconds));
        return RestClient.builder()
                .requestFactory(requestFactory)
                .requestInterceptor(ssrfInterceptor)
                .build();
    }

    private static RestClient.RequestBodySpec buildRequest(
            RestClient restClient, String url, @Nullable String apiKey, Object body) {
        RestClient.RequestBodySpec spec = restClient.post()
                .uri(url)
                .body(body);
        if (apiKey != null && !apiKey.isBlank()) {
            spec = spec.header(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey);
        }
        return spec;
    }

    public record ExternalValidationResult(
            @Nullable String verdict,
            @Nullable String reason) {}

    // sent : the service acknowledged the trigger (2xx). immediateVerdict : ALLOWED/BLOCKED verdict
    // already in that acknowledgment, null when it is to come by callback.
    public record AsyncTriggerResult(boolean sent, @Nullable ExternalValidationResult immediateVerdict) {
        public static final AsyncTriggerResult NOT_SENT = new AsyncTriggerResult(false, null);
    }
}
