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


package com.silicaproxy.service.decision;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import com.silicaproxy.properties.SilicaProxyProperties;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

// Holds client requests until the callback of an async external validation resolves their token
// (services.<name>.await-verdict-seconds).
//
// One poller per instance : every await-poll-interval-millis, a single query returns which of the
// awaited tokens are still PENDING, and the requests waiting on every other token are woken up. The
// database load therefore does not grow with the number of held requests, and a callback received
// by another instance is seen as well, since the state is read from the shared table.
//
// The check is on the state, not on an event : a token resolved before its request registered is
// detected by the next poll, so no wake-up is lost.
@Component
@NullMarked
public class AsyncVerdictWaiter {

    private static final Logger LOG = LoggerFactory.getLogger(AsyncVerdictWaiter.class);
    // Bounds the IN list of one query (PostgreSQL accepts up to 32767 bind parameters).
    private static final int MAX_TOKENS_PER_QUERY = 1000;
    private static final Duration POLL_FAILURE_LOG_INTERVAL = Duration.ofMinutes(1);

    private final ExternalValidationCacheDao cacheDao;
    private final ExternalValidationMetrics metrics;
    private final long pollIntervalMillis;
    // A token may be awaited by several requests at once (the .pom and the .jar of the same version).
    private final Map<UUID, Set<CompletableFuture<Void>>> waiters = new ConcurrentHashMap<>();
    private final AtomicInteger inProgress = new AtomicInteger();
    private final ScheduledExecutorService poller = Executors.newSingleThreadScheduledExecutor(
            Thread.ofVirtual().name("SilicaProxy-VerdictWaiter").factory());
    private volatile Instant lastPollFailureLog = Instant.EPOCH;

    public AsyncVerdictWaiter(ExternalValidationCacheDao cacheDao, ExternalValidationMetrics metrics,
            SilicaProxyProperties properties, MeterRegistry meterRegistry) {
        this.cacheDao = cacheDao;
        this.metrics = metrics;
        this.pollIntervalMillis = properties.externalValidation().awaitPollIntervalMillis();
        Gauge.builder(Metrics.AWAIT_IN_PROGRESS_METRIC, inProgress, AtomicInteger::get)
                .description("Requests currently held waiting for an async external validation verdict")
                .register(meterRegistry);
    }

    @PostConstruct
    void start() {
        poller.scheduleWithFixedDelay(this::poll, pollIntervalMillis, pollIntervalMillis, TimeUnit.MILLISECONDS);
    }

    @PreDestroy
    void stop() {
        poller.shutdownNow();
    }

    // Holds the caller until the PENDING entry of this service and version is resolved, or deadline
    // passes. True when it was resolved in time : the caller then reads the verdict itself. False at
    // once, without waiting, when there is no valid PENDING entry to wait for (trigger not
    // acknowledged, entry already resolved).
    public boolean awaitVerdict(String serviceName, String packageName, String ecosystem, String version,
            Instant deadline) {
        Optional<UUID> token = cacheDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version)
                .filter(e -> "PENDING".equals(e.status()) && e.expiresAt().isAfter(Instant.now()))
                .map(ExternalValidationCacheEntry::callbackToken);
        if (token.isEmpty()) {
            return false;
        }
        Instant start = Instant.now();
        Duration remaining = Duration.between(start, deadline);
        boolean resolved = !remaining.isNegative() && await(token.get(), remaining);
        Duration waited = Duration.between(start, Instant.now());
        metrics.recordAwaitMetric(serviceName, resolved ? Metrics.OUTCOME_RESOLVED : Metrics.OUTCOME_EXPIRED, waited);
        LOG.debug("External validation {} for {}/{}@{}: waited {} ms for the async verdict, {}",
                serviceName, ecosystem, packageName, version, waited.toMillis(), resolved ? "resolved" : "expired");
        return resolved;
    }

    // Blocks until the entry of token is no longer a valid PENDING, or timeout elapses.
    private boolean await(UUID token, Duration timeout) {
        CompletableFuture<Void> resolved = new CompletableFuture<>();
        // Added inside compute, atomically per key : a concurrent last waiter removing the token's set
        // in its finally can then never drop this future along with it.
        waiters.compute(token, (t, set) -> {
            Set<CompletableFuture<Void>> futures = set != null ? set : ConcurrentHashMap.newKeySet();
            futures.add(resolved);
            return futures;
        });
        inProgress.incrementAndGet();
        try {
            resolved.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            return true;
        } catch (TimeoutException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            // Never completed exceptionally ; kept to satisfy the checked signature.
            return false;
        } finally {
            inProgress.decrementAndGet();
            // Removes the token once its last waiter is gone, so the polled set only holds live waits.
            waiters.computeIfPresent(token, (t, set) -> {
                set.remove(resolved);
                return set.isEmpty() ? null : set;
            });
        }
    }

    // Package-private for tests : one polling round.
    void poll() {
        if (waiters.isEmpty()) {
            return;
        }
        try {
            List<UUID> tokens = new ArrayList<>(waiters.keySet());
            for (int from = 0; from < tokens.size(); from += MAX_TOKENS_PER_QUERY) {
                List<UUID> batch = tokens.subList(from, Math.min(from + MAX_TOKENS_PER_QUERY, tokens.size()));
                Set<UUID> stillPending = cacheDao.findStillPendingTokens(batch);
                for (UUID token : batch) {
                    if (!stillPending.contains(token)) {
                        Set<CompletableFuture<Void>> futures = waiters.get(token);
                        if (futures != null) {
                            futures.forEach(f -> f.complete(null));
                        }
                    }
                }
            }
        } catch (RuntimeException e) {
            // The held requests then run out their wait and get the temporary 429, as without waiting.
            // Logged at most once a minute : a database outage would otherwise log every interval.
            Instant now = Instant.now();
            if (now.isAfter(lastPollFailureLog.plus(POLL_FAILURE_LOG_INTERVAL))) {
                lastPollFailureLog = now;
                LOG.warn("Async verdict poll failed, {} held request(s) keep waiting: {}",
                        inProgress.get(), e.toString());
            }
        }
    }
}
