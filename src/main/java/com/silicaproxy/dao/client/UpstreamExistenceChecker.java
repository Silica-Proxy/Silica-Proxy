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
import com.silicaproxy.dao.policy.UpstreamHeadCacheDao;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * HEAD on the URL the client requested, run before an external validation service is called
 * (services.&lt;name&gt;.head-check). The outcome is cached in PostgreSQL so the HEAD is not repeated
 * for every validation of the same artifact. Only EXISTS and NOT_FOUND are cached ; an error,
 * a timeout or a 429 yields UNKNOWN, which the caller treats as "not checked" (service called).
 */
@Component
@NullMarked
public class UpstreamExistenceChecker {

    private static final Logger LOG = LoggerFactory.getLogger(UpstreamExistenceChecker.class);

    public enum Status { EXISTS, NOT_FOUND, UNKNOWN }

    private static final String EXISTS = "EXISTS";
    private static final String NOT_FOUND = "NOT_FOUND";

    private final HttpClient httpClient;
    private final SsrfInterceptor ssrfInterceptor;
    private final HttpsUpgradePolicy httpsUpgradePolicy;
    private final UpstreamThrottle upstreamThrottle;
    private final UpstreamHeadCacheDao cacheDao;
    // One RestClient per distinct head-check-timeout-seconds, sharing the HttpClient pool
    private final Map<Integer, RestClient> restClients = new ConcurrentHashMap<>();

    public UpstreamExistenceChecker(
            @Qualifier("externalValidationHttpClient") HttpClient httpClient,
            SsrfInterceptor ssrfInterceptor,
            HttpsUpgradePolicy httpsUpgradePolicy,
            UpstreamThrottle upstreamThrottle,
            UpstreamHeadCacheDao cacheDao) {
        this.httpClient = httpClient;
        this.ssrfInterceptor = ssrfInterceptor;
        this.httpsUpgradePolicy = httpsUpgradePolicy;
        this.upstreamThrottle = upstreamThrottle;
        this.cacheDao = cacheDao;
    }

    @Timed(value = "silicaproxy.dao.upstreamhead.check",
            description = "Duration of the HEAD check run before an external validation service",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Status check(String fullUrl, int timeoutSeconds, int cacheTtlMinutes) {
        // Same upgrade as the relay : Nexus asks in plain HTTP, the upstream answers 403 to it.
        String url = httpsUpgradePolicy.upgrade(fullUrl);

        Optional<Status> cached = readCache(url);
        if (cached.isPresent()) {
            return cached.get();
        }

        @Nullable URI uri = UpstreamThrottle.parse(url).orElse(null);
        if (uri != null && upstreamThrottle.suspendedUntil(uri).isPresent()) {
            upstreamThrottle.recordSkipped(uri, UpstreamThrottle.Origin.RELAY);
            return Status.UNKNOWN;
        }

        try {
            restClients.computeIfAbsent(timeoutSeconds, this::buildRestClient)
                    .head()
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity();
            if (uri != null) {
                upstreamThrottle.recordSuccess(uri);
            }
            writeCache(url, EXISTS, cacheTtlMinutes);
            return Status.EXISTS;
        } catch (HttpClientErrorException.NotFound e) {
            writeCache(url, NOT_FOUND, cacheTtlMinutes);
            return Status.NOT_FOUND;
        } catch (HttpClientErrorException.TooManyRequests e) {
            if (uri != null) {
                upstreamThrottle.recordThrottled(uri,
                        e.getResponseHeaders() == null ? null : e.getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER),
                        UpstreamThrottle.Origin.RELAY);
            }
            return Status.UNKNOWN;
        } catch (Exception e) {
            LOG.debug("Upstream HEAD check failed for {} : {}", url, e.getMessage());
            return Status.UNKNOWN;
        }
    }

    private Optional<Status> readCache(String url) {
        try {
            Optional<String> stored = cacheDao.findStatus(url);
            if (stored.isPresent() && EXISTS.equals(stored.get())) {
                return Optional.of(Status.EXISTS);
            }
            if (stored.isPresent() && NOT_FOUND.equals(stored.get())) {
                return Optional.of(Status.NOT_FOUND);
            }
            return Optional.empty();
        } catch (Exception e) {
            // A cache read failure must not block validation : fall through to the HEAD
            LOG.warn("Upstream HEAD cache read failed for {} : {}", url, e.getMessage());
            return Optional.empty();
        }
    }

    private void writeCache(String url, String status, int cacheTtlMinutes) {
        try {
            cacheDao.upsert(url, status, Instant.now().plus(cacheTtlMinutes, ChronoUnit.MINUTES));
        } catch (Exception e) {
            LOG.warn("Upstream HEAD cache write failed for {} : {}", url, e.getMessage());
        }
    }

    private RestClient buildRestClient(int timeoutSeconds) {
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(timeoutSeconds));
        return RestClient.builder()
                .requestFactory(requestFactory)
                .requestInterceptor(ssrfInterceptor)
                .build();
    }
}
