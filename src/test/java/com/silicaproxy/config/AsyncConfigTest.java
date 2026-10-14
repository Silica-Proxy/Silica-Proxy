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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class AsyncConfigTest {

    @Test
    void shouldDiscardOldestAndCountItWhenQueueIsFull() throws InterruptedException {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CountDownLatch release = new CountDownLatch(1);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(1), new AsyncConfig.CountingDiscardOldestPolicy(registry));
        AtomicBoolean oldestRan = new AtomicBoolean();
        AtomicBoolean newestRan = new AtomicBoolean();
        try {
            executor.execute(() -> awaitQuietly(release)); // occupies the only thread
            executor.execute(() -> oldestRan.set(true));    // fills the queue, then gets discarded
            executor.execute(() -> newestRan.set(true));    // overflow: replaces the oldest

            assertThat(registry.get(Metrics.AUDIT_LOG_WRITES_METRIC)
                    .tag(Metrics.TAG_OUTCOME, Metrics.OUTCOME_DROPPED)
                    .counter().count()).isEqualTo(1.0);
        } finally {
            release.countDown();
            executor.shutdown();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        }
        assertThat(oldestRan).isFalse();
        assertThat(newestRan).isTrue();
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
