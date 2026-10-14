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

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolver.LookupPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class SsrfSafeInetAddressResolverProviderTest {

    private static final LookupPolicy POLICY = LookupPolicy.of(LookupPolicy.IPV4);

    /** Fake builtin resolver that records every lookup and answers with a fixed public address. */
    private static final class RecordingResolver implements InetAddressResolver {
        final List<String> lookups = new ArrayList<>();

        @Override
        public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy) {
            lookups.add(host);
            return Stream.of(InetAddress.ofLiteral("93.184.216.34"));
        }

        @Override
        public String lookupByAddress(byte[] addr) {
            throw new UnsupportedOperationException();
        }
    }

    private static InetAddressResolver resolverWith(int maxEntries, RecordingResolver delegate) {
        return new SsrfSafeInetAddressResolverProvider(maxEntries).resolverFor(delegate);
    }

    @Test
    void shouldServeRepeatedLookupFromCache() throws Exception {
        RecordingResolver delegate = new RecordingResolver();
        InetAddressResolver resolver = resolverWith(10, delegate);

        resolver.lookupByName("example.com", POLICY).toList();
        resolver.lookupByName("example.com", POLICY).toList();

        assertThat(delegate.lookups).containsExactly("example.com");
    }

    @Test
    void shouldNeverEvictHostJustResolvedWhenOverCapacity() throws Exception {
        int maxEntries = 5;
        RecordingResolver delegate = new RecordingResolver();
        InetAddressResolver resolver = resolverWith(maxEntries, delegate);

        for (int i = 0; i < maxEntries; i++) {
            resolver.lookupByName("filler" + i + ".example.com", POLICY).toList();
        }
        // Validator lookup overflows the cap; the connection lookup right after must hit the cache,
        // otherwise a second DNS query reopens the rebinding window.
        resolver.lookupByName("target.example.com", POLICY).toList();
        resolver.lookupByName("target.example.com", POLICY).toList();

        assertThat(delegate.lookups).filteredOn("target.example.com"::equals).hasSize(1);
    }

    @Test
    void shouldEvictOldestInsertionsFirstWhenOverCapacity() throws Exception {
        int maxEntries = 5;
        RecordingResolver delegate = new RecordingResolver();
        InetAddressResolver resolver = resolverWith(maxEntries, delegate);

        for (int i = 0; i <= maxEntries; i++) {
            resolver.lookupByName("host" + i + ".example.com", POLICY).toList();
            Thread.sleep(2);
        }
        delegate.lookups.clear();

        // Overflow evicts down to 90% of the cap (4 entries): host0 and host1 are the oldest.
        resolver.lookupByName("host4.example.com", POLICY).toList();
        resolver.lookupByName("host0.example.com", POLICY).toList();

        assertThat(delegate.lookups).containsExactly("host0.example.com");
    }
}
