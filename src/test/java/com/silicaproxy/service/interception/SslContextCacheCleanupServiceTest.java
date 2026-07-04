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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SslContextCacheCleanupServiceTest {

    @Test
    void shouldEvictWithA24HourTtl() {
        HostSslContextCache hostSslContextCache = mock(HostSslContextCache.class);
        when(hostSslContextCache.evictStaleEntries(org.mockito.ArgumentMatchers.any())).thenReturn(0);
        SslContextCacheCleanupService cleanupService = new SslContextCacheCleanupService(hostSslContextCache);

        cleanupService.evictStaleHostContexts();

        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(hostSslContextCache).evictStaleEntries(ttlCaptor.capture());
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofHours(24));
    }

    @Test
    void shouldNotThrowWhenNoEntriesEvicted() {
        HostSslContextCache hostSslContextCache = mock(HostSslContextCache.class);
        when(hostSslContextCache.evictStaleEntries(org.mockito.ArgumentMatchers.any())).thenReturn(3);
        SslContextCacheCleanupService cleanupService = new SslContextCacheCleanupService(hostSslContextCache);

        cleanupService.evictStaleHostContexts();

        verify(hostSslContextCache).evictStaleEntries(Duration.ofHours(24));
    }
}
