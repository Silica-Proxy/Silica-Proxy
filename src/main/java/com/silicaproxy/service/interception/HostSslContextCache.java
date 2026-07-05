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

import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

/**
 * Per-host SSLContext cache (generated cert + keypair) used by {@link SslMitmService} for MITM
 * TLS interception. Bounded by inactivity (sliding last-access timestamp, refreshed on every
 * {@link #getOrCompute}, reclaimed by {@link #evictStaleEntries}) AND by a hard size cap: a
 * client sending CONNECT to many thousands of distinct hostnames within the TTL window would
 * otherwise force that many RSA-2048 key generations and cache entries before any of them goes
 * stale -- a CPU/memory DoS vector. Same size-cap approach as
 * {@link com.silicaproxy.config.SsrfSafeInetAddressResolverProvider}, which guards against the
 * analogous risk for DNS resolutions.
 */
@Component
@NullMarked
public class HostSslContextCache {

    private final Map<String, CachedContext> cache = new ConcurrentHashMap<>();
    private final int maxEntries;

    private record CachedContext(SSLContext sslContext, AtomicReference<Instant> lastAccessedAt) {}

    public HostSslContextCache(SilicaProxyProperties properties) {
        this.maxEntries = properties.sslMitm().contextCacheMaxEntries();
    }

    /** Test-only : no size cap enforced (defaults to Integer.MAX_VALUE). */
    HostSslContextCache() {
        this.maxEntries = Integer.MAX_VALUE;
    }

    /**
     * Returns the cached SSLContext for {@code host}, computing and storing it via
     * {@code computeFunction} on a cache miss. Refreshes the entry's last-access timestamp on
     * every call (sliding TTL), whether it was already cached or just computed.
     */
    public SSLContext getOrCompute(String host, Function<String, SSLContext> computeFunction) {
        CachedContext cached = cache.computeIfAbsent(host,
                h -> new CachedContext(computeFunction.apply(h), new AtomicReference<>(Instant.now())));
        cached.lastAccessedAt().set(Instant.now());
        evictIfOversized();
        return cached.sslContext();
    }

    /** Evicts entries not accessed within {@code ttl}. Returns the number of entries evicted. */
    public int evictStaleEntries(Duration ttl) {
        Instant cutoff = Instant.now().minus(ttl);
        int sizeBefore = cache.size();
        cache.entrySet().removeIf(entry -> entry.getValue().lastAccessedAt().get().isBefore(cutoff));
        return sizeBefore - cache.size();
    }

    private void evictIfOversized() {
        if (cache.size() <= maxEntries) {
            return;
        }
        int excess = cache.size() - maxEntries;
        if (excess > 0) {
            cache.keySet().stream().limit(excess).forEach(cache::remove);
        }
    }

    public int size() {
        return cache.size();
    }
}
