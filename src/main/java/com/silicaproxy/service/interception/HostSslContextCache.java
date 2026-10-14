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
import java.util.Comparator;
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
 *
 * <p>When the cap is exceeded, the least-recently-accessed entries are evicted first (never the
 * host just requested), down to 90% of the cap so a flood of new hosts
 * does not trigger a sort on every insertion. Hot hosts such as the public registries therefore
 * survive a flood instead of being dropped in hash-bucket order and regenerated over and over.
 */
@Component
@NullMarked
public class HostSslContextCache {

    private static final double EVICTION_TARGET_RATIO = 0.9;

    private final Map<String, CachedContext> cache = new ConcurrentHashMap<>();
    private final int maxEntries;

    private record CachedContext(SSLContext sslContext, AtomicReference<Instant> lastAccessedAt) {}

    /** Snapshot of an entry's last access, so the sort is not disturbed by concurrent touches. */
    private record EvictionCandidate(String host, CachedContext context, Instant lastAccessedAt) {}

    public HostSslContextCache(SilicaProxyProperties properties) {
        this.maxEntries = properties.sslMitm().contextCacheMaxEntries();
    }

    /** Test-only : no size cap enforced (defaults to Integer.MAX_VALUE). */
    HostSslContextCache() {
        this(Integer.MAX_VALUE);
    }

    /** Test-only : explicit size cap. */
    HostSslContextCache(int maxEntries) {
        this.maxEntries = maxEntries;
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
        evictIfOversized(host);
        return cached.sslContext();
    }

    /** Evicts entries not accessed within {@code ttl}. Returns the number of entries evicted. */
    public int evictStaleEntries(Duration ttl) {
        Instant cutoff = Instant.now().minus(ttl);
        int sizeBefore = cache.size();
        cache.entrySet().removeIf(entry -> entry.getValue().lastAccessedAt().get().isBefore(cutoff));
        return sizeBefore - cache.size();
    }

    private void evictIfOversized(String justAccessed) {
        if (cache.size() <= maxEntries) {
            return;
        }
        int excess = cache.size() - Math.max(1, (int) (maxEntries * EVICTION_TARGET_RATIO));
        cache.entrySet().stream()
                .filter(entry -> !entry.getKey().equals(justAccessed))
                .map(entry -> new EvictionCandidate(entry.getKey(), entry.getValue(),
                        entry.getValue().lastAccessedAt().get()))
                .sorted(Comparator.comparing(EvictionCandidate::lastAccessedAt))
                .limit(Math.max(0, excess))
                .forEach(candidate -> cache.remove(candidate.host(), candidate.context()));
    }

    public int size() {
        return cache.size();
    }
}
