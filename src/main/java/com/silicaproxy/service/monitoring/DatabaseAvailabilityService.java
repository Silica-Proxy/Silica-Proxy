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


package com.silicaproxy.service.monitoring;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.sync.HealthCheckDao;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tracks whether the database is reachable, so {@code ProxyController} can block every request
 * while it is not : without the database, policies, blacklists, vulnerabilities and audit logs
 * are all out of reach, and nothing the proxy relays could be vetted or traced.
 *
 * <p>Probed with a {@code SELECT 1} on every instance (no ShedLock : each instance has its own
 * pool) every {@code silicaproxy.proxy.database-check-interval-seconds}, rather than on each
 * request, to keep the hot path free of an extra round-trip. A {@code DataAccessException} seen
 * on the request path marks it unavailable at once through {@link #markUnavailable}, so an outage
 * is not served for up to one interval ; only a successful probe marks it available again.
 * Starts available : Flyway has just migrated the database when the application is up.
 */
@Service
@NullMarked
public class DatabaseAvailabilityService {

    private static final Logger LOG = LoggerFactory.getLogger(DatabaseAvailabilityService.class);

    private final HealthCheckDao healthCheckDao;
    private final AtomicBoolean available = new AtomicBoolean(true);

    public DatabaseAvailabilityService(HealthCheckDao healthCheckDao, MeterRegistry meterRegistry) {
        this.healthCheckDao = healthCheckDao;
        Gauge.builder(Metrics.DATABASE_AVAILABLE_METRIC, available, flag -> flag.get() ? 1 : 0)
                .description("1 while the database is reachable, 0 while every proxy request is blocked")
                .register(meterRegistry);
    }

    public boolean isAvailable() {
        return available.get();
    }

    @Scheduled(fixedDelayString = "${silicaproxy.proxy.database-check-interval-seconds:5}000")
    public void probe() {
        try {
            if (healthCheckDao.isDatabaseReachable()) {
                if (available.compareAndSet(false, true)) {
                    LOG.info("Database reachable again : proxy requests are no longer blocked");
                }
                return;
            }
            markUnavailable("SELECT 1 returned an unexpected result");
        } catch (RuntimeException e) {
            markUnavailable(String.valueOf(e.getMessage()));
        }
    }

    public void markUnavailable(RuntimeException cause) {
        markUnavailable(String.valueOf(cause.getMessage()));
    }

    private void markUnavailable(String reason) {
        if (available.compareAndSet(true, false)) {
            LOG.error("Database unreachable : every proxy request is blocked until it is back ({})", reason);
        }
    }
}
