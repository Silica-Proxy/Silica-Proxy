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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicLong;

@Configuration
@EnableAsync
@NullMarked
public class AsyncConfig {

    @Bean(name = "auditTaskExecutor")
    public Executor auditTaskExecutor(MeterRegistry meterRegistry) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // core == max on purpose: ThreadPoolExecutor only grows past the core size once the queue
        // is already full, so with core < max the extra writers would only start when audit
        // entries are already being dropped. Virtual threads make 20 idle writers cheap; the
        // real cost is up to 20 Hikari connections under load (pool sized accordingly).
        executor.setCorePoolSize(20);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(5000);
        executor.setThreadNamePrefix("SilicaProxy-Audit-");
        executor.setThreadFactory(Thread.ofVirtual().name("SilicaProxy-Audit-", 0).factory());
        executor.setRejectedExecutionHandler(new CountingDiscardOldestPolicy(meterRegistry));
        executor.initialize();
        return executor;
    }

    @Bean(name = "externalValidationExecutor")
    public Executor externalValidationExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("SilicaProxy-ExtVal-");
        executor.setThreadFactory(Thread.ofVirtual().name("SilicaProxy-ExtVal-", 0).factory());
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }

    /**
     * Same as {@link ThreadPoolExecutor.DiscardOldestPolicy} (drops the oldest queued audit task,
     * never blocks the proxy request on an INSERT), but counts each drop as {@code outcome=DROPPED}
     * on the audit write counter: a dropped task never reaches {@code AuditLogService.logAudit},
     * so without this the loss would be invisible.
     */
    static final class CountingDiscardOldestPolicy implements RejectedExecutionHandler {

        private static final Logger LOG = LoggerFactory.getLogger(CountingDiscardOldestPolicy.class);
        static final long LOG_EVERY = 1000;

        private final Counter droppedCounter;
        private final AtomicLong dropped = new AtomicLong();

        CountingDiscardOldestPolicy(MeterRegistry meterRegistry) {
            this.droppedCounter = Counter.builder(Metrics.AUDIT_LOG_WRITES_METRIC)
                    .description("Total number of audit log write attempts, by outcome (SUCCESS/FAILURE/DROPPED)")
                    .tag(Metrics.TAG_OUTCOME, Metrics.OUTCOME_DROPPED)
                    .register(meterRegistry);
        }

        @Override
        public void rejectedExecution(Runnable task, ThreadPoolExecutor executor) {
            if (executor.isShutdown()) {
                return;
            }
            if (executor.getQueue().poll() != null) {
                recordDrop(executor);
            }
            executor.execute(task);
        }

        private void recordDrop(ThreadPoolExecutor executor) {
            droppedCounter.increment();
            long total = dropped.incrementAndGet();
            // Rate-limited: a saturated queue rejects thousands of tasks per second.
            if (total == 1 || total % LOG_EVERY == 0) {
                LOG.warn("Audit executor queue full ({} queued): audit log entry dropped ({} dropped so far)",
                        executor.getQueue().size(), total);
            }
        }
    }
}
