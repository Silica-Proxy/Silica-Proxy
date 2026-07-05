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
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class HostSslContextCacheTest {

    private static SilicaProxyProperties makeProperties(int contextCacheMaxEntries) {
        return new SilicaProxyProperties(
            new SilicaProxyProperties.QuarantineProperties(false, 0, true, Map.of()),
            new SilicaProxyProperties.DeprecationProperties(false, Map.of()),
            new SilicaProxyProperties.SeverityThresholdProperties(false, "NONE", 11.0, Map.of()),
            Map.of(),
            new SilicaProxyProperties.GitOpsProperties(false, "http://example.com", "/rules", null, 60),
            new SilicaProxyProperties.CorporateProxyProperties(false, "proxy.example.com", 8080, "localhost",
                new SilicaProxyProperties.CorporateProxyScopeProperties(false, false, false, false, false)),
            new SilicaProxyProperties.RegistriesProperties("http://npm.example.com", "http://pypi.example.com", "http://maven.example.com"),
            new SilicaProxyProperties.ProxyProperties(0, 30, 60),
            new SilicaProxyProperties.SecurityProperties(
                new SilicaProxyProperties.SsrfProtectionProperties(false),
                new SilicaProxyProperties.ApiAuthProperties(false, null, null)),
            new SilicaProxyProperties.HttpClientProperties(5, 5, 5, 1),
            new SilicaProxyProperties.SslMitmProperties(null, null, null, contextCacheMaxEntries),
            new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
            new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
            new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100),
            new SilicaProxyProperties.ExternalValidationProperties(null, false, Map.of())
        );
    }

    private SSLContext newContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        return ctx;
    }

    @Test
    void shouldComputeOnlyOnceForRepeatedHost() throws Exception {
        HostSslContextCache cache = new HostSslContextCache();
        AtomicInteger computeCount = new AtomicInteger();

        SSLContext first = cache.getOrCompute("example.com", h -> {
            computeCount.incrementAndGet();
            try {
                return newContext();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        SSLContext second = cache.getOrCompute("example.com", h -> {
            computeCount.incrementAndGet();
            try {
                return newContext();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        assertThat(second).isSameAs(first);
        assertThat(computeCount.get()).isEqualTo(1);
    }

    @Test
    void shouldNotEvictEntryAccessedWithinTtl() throws Exception {
        HostSslContextCache cache = new HostSslContextCache();
        cache.getOrCompute("active.example.com", h -> uncheckedNewContext());

        int evicted = cache.evictStaleEntries(Duration.ofHours(24));

        assertThat(evicted).isZero();
        assertThat(cache.size()).isEqualTo(1);
    }

    @Test
    void shouldEvictEntryOlderThanTtl() throws Exception {
        HostSslContextCache cache = new HostSslContextCache();
        cache.getOrCompute("stale.example.com", h -> uncheckedNewContext());

        // A TTL of zero means "anything not accessed in the last instant" -- i.e. everything
        // already stored, since accessing it just now is still "not after" a cutoff of now().
        int evicted = cache.evictStaleEntries(Duration.ZERO.minusNanos(1));

        assertThat(evicted).isEqualTo(1);
        assertThat(cache.size()).isZero();
    }

    @Test
    void shouldPropagateComputeFunctionFailureWithoutCachingAnEntry() {
        HostSslContextCache cache = new HostSslContextCache();

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> cache.getOrCompute("fail.example.com", h -> {
            throw new RuntimeException("boom");
        })).isInstanceOf(RuntimeException.class).hasMessage("boom");

        assertThat(cache.size()).isZero();
    }

    @Test
    void shouldEvictOldestEntriesWhenOverCapacity() throws Exception {
        int maxEntries = 3;
        HostSslContextCache cache = new HostSslContextCache(makeProperties(maxEntries));

        for (int i = 0; i < maxEntries + 5; i++) {
            cache.getOrCompute("host" + i + ".example.com", h -> uncheckedNewContext());
        }

        assertThat(cache.size()).isLessThanOrEqualTo(maxEntries);
    }

    private SSLContext uncheckedNewContext() {
        try {
            return newContext();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
