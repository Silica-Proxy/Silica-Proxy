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


package com.silicaproxy.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Closes the DNS-rebinding TOCTOU gap in {@link SsrfValidator}: without this, {@code
 * InetAddress.getAllByName(host)} in the validator and the independent resolution the JDK
 * {@code HttpClient} performs moments later when actually connecting are two separate DNS
 * queries, and a malicious authoritative server can answer the first with a public IP (passing
 * validation) and the second with a loopback/private address (the real target). Registered as a
 * JEP 418 {@link InetAddressResolverProvider} (see {@code META-INF/services}), this makes every
 * {@code InetAddress} resolution in the JVM -- including both of the above -- share a short-lived
 * cache keyed by hostname, so the address the validator checks is guaranteed to be the same one
 * the subsequent connection uses.
 *
 * <p>Bounded by a hard entry cap rather than relying solely on TTL expiry: the hostnames flowing
 * through here are attacker-influenced (any host reachable through the proxy's registry/security
 * API calls), so an unbounded map would itself be a memory-exhaustion vector -- the same class of
 * issue {@link com.silicaproxy.service.interception.HostSslContextCache} guards against for the
 * per-host MITM SSLContext cache.
 */
public final class SsrfSafeInetAddressResolverProvider extends InetAddressResolverProvider {

    private static final Duration CACHE_TTL = Duration.ofSeconds(30);
    private static final int MAX_CACHE_ENTRIES = 2000;

    private final ConcurrentHashMap<String, CachedResolution> cache = new ConcurrentHashMap<>();

    private record CachedResolution(List<InetAddress> addresses, Instant expiresAt) {
        boolean isExpired(Instant now) {
            return !expiresAt.isAfter(now);
        }
    }

    @Override
    public InetAddressResolver get(Configuration configuration) {
        return new CachingResolver(configuration.builtinResolver());
    }

    @Override
    public String name() {
        return "silicaproxy-ssrf-safe-resolver";
    }

    private void evictIfOversized() {
        if (cache.size() <= MAX_CACHE_ENTRIES) {
            return;
        }
        Instant now = Instant.now();
        cache.values().removeIf(entry -> entry.isExpired(now));
        int excess = cache.size() - MAX_CACHE_ENTRIES;
        if (excess > 0) {
            cache.keySet().stream().limit(excess).forEach(cache::remove);
        }
    }

    private final class CachingResolver implements InetAddressResolver {

        private final InetAddressResolver delegate;

        private CachingResolver(InetAddressResolver delegate) {
            this.delegate = delegate;
        }

        @Override
        public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy) throws UnknownHostException {
            Instant now = Instant.now();
            CachedResolution cached = cache.get(host);
            if (cached != null && !cached.isExpired(now)) {
                return cached.addresses().stream();
            }
            List<InetAddress> resolved = delegate.lookupByName(host, lookupPolicy).toList();
            cache.put(host, new CachedResolution(resolved, now.plus(CACHE_TTL)));
            evictIfOversized();
            return resolved.stream();
        }

        @Override
        public String lookupByAddress(byte[] addr) throws UnknownHostException {
            return delegate.lookupByAddress(addr);
        }
    }
}
