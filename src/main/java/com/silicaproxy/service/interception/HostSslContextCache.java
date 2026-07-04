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
 * TLS interception. Bounded by inactivity rather than by size: entries carry a sliding
 * last-access timestamp, refreshed on every {@link #getOrCompute}, so a host hit repeatedly by
 * ongoing build traffic (npm/PyPI/Maven registries) never gets evicted, while a host seen once
 * (a temporary mirror, a typo) is reclaimed once {@link #evictStaleEntries} runs past it.
 * Without this, every distinct CONNECT target ever seen over a long-running instance's lifetime
 * would stay referenced forever. Eviction is driven externally (see
 * {@code SslContextCacheCleanupService}) so this class only holds the cache mechanics.
 */
@Component
@NullMarked
public class HostSslContextCache {

    private final Map<String, CachedContext> cache = new ConcurrentHashMap<>();

    private record CachedContext(SSLContext sslContext, AtomicReference<Instant> lastAccessedAt) {}

    /**
     * Returns the cached SSLContext for {@code host}, computing and storing it via
     * {@code computeFunction} on a cache miss. Refreshes the entry's last-access timestamp on
     * every call (sliding TTL), whether it was already cached or just computed.
     */
    public SSLContext getOrCompute(String host, Function<String, SSLContext> computeFunction) {
        CachedContext cached = cache.computeIfAbsent(host,
                h -> new CachedContext(computeFunction.apply(h), new AtomicReference<>(Instant.now())));
        cached.lastAccessedAt().set(Instant.now());
        return cached.sslContext();
    }

    /** Evicts entries not accessed within {@code ttl}. Returns the number of entries evicted. */
    public int evictStaleEntries(Duration ttl) {
        Instant cutoff = Instant.now().minus(ttl);
        int sizeBefore = cache.size();
        cache.entrySet().removeIf(entry -> entry.getValue().lastAccessedAt().get().isBefore(cutoff));
        return sizeBefore - cache.size();
    }

    public int size() {
        return cache.size();
    }
}
