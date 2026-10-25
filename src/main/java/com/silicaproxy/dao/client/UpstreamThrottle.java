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

package com.silicaproxy.dao.client;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.properties.UpstreamThrottleProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.DoubleSupplier;

/**
 * Remembers the upstream hosts that answered 429 (Too Many Requests) and suspends every call to
 * them until they may be asked again : the {@code Retry-After} they sent, or a backoff doubled on
 * each consecutive 429 when they sent none, always within [min, max]. Shared by the relay
 * ({@link ProxyStreamClient}), the publish-date lookups ({@link RegistryClient}) and the security
 * APIs ({@link OsvClient}, {@link DepsDevClient}) : a host that rate-limits one of them is left
 * alone by all, instead of each retry extending the rate limit.
 *
 * <p>Per instance, in memory : each instance learns the 429 on its own, at the cost of one extra
 * call per instance. The first 2xx after a suspension ended resets the backoff. Bounded in size,
 * since the relay reaches arbitrary hosts : past {@link #MAX_HOSTS}, a new host is not suspended.
 */
@Component
@NullMarked
public class UpstreamThrottle {

    private static final Logger LOG = LoggerFactory.getLogger(UpstreamThrottle.class);
    static final int MAX_HOSTS = 1024;
    // A host-supplied Retry-After is never shortened : the jitter only delays, by up to this much.
    private static final double JITTER_RATIO = 0.2;
    // Thread-safe ; only drawn on a 429, so its cost does not matter.
    private static final SecureRandom JITTER = new SecureRandom();

    /** Which proxy component made the call, for the metrics. */
    public enum Origin { RELAY, REGISTRY, SECURITY_API }

    private record Suspension(Instant until, int strikes) {}

    private final UpstreamThrottleProperties properties;
    private final Clock clock;
    private final DoubleSupplier random;
    private final Set<String> knownHosts;
    private final MeterRegistry meterRegistry;
    private final Map<String, Suspension> suspensions = new ConcurrentHashMap<>();

    @Autowired
    public UpstreamThrottle(UpstreamThrottleProperties properties, SilicaProxyProperties proxyProperties,
            MeterRegistry meterRegistry) {
        this(properties, knownHosts(proxyProperties), meterRegistry, Clock.systemUTC(),
                JITTER::nextDouble);
    }

    UpstreamThrottle(UpstreamThrottleProperties properties, Set<String> knownHosts, MeterRegistry meterRegistry,
            Clock clock, DoubleSupplier random) {
        this.properties = properties;
        this.knownHosts = Set.copyOf(knownHosts);
        this.meterRegistry = meterRegistry;
        this.clock = clock;
        this.random = random;
        Gauge.builder(Metrics.UPSTREAM_SUSPENDED_HOSTS_METRIC, this, UpstreamThrottle::suspendedHostCount)
                .description("Upstream hosts currently left alone after a 429")
                .register(meterRegistry);
    }

    /** Default settings, no configured host : for the components built outside Spring (tests). */
    public static UpstreamThrottle standalone() {
        return new UpstreamThrottle(UpstreamThrottleProperties.defaults(), Set.of(), new SimpleMeterRegistry(),
                Clock.systemUTC(), () -> 0.5);
    }

    private static Set<String> knownHosts(SilicaProxyProperties properties) {
        Set<String> hosts = new HashSet<>();
        addHost(hosts, properties.registries().npmUrl());
        addHost(hosts, properties.registries().pypiUrl());
        addHost(hosts, properties.registries().mavenUrl());
        properties.apiFallback().values().forEach(api -> addHost(hosts, api.url()));
        return hosts;
    }

    private static void addHost(Set<String> hosts, @Nullable String url) {
        parse(url).flatMap(UpstreamThrottle::hostKey).ifPresent(hosts::add);
    }

    /**
     * {@code url} as a URI, only to tell its host : the request itself keeps going through the
     * HTTP client's own URI handling. Empty when unparseable -- no suspension applies then.
     */
    public static Optional<URI> parse(@Nullable String url) {
        if (url == null || url.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(URI.create(url.trim()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public UpstreamThrottleProperties properties() {
        return properties;
    }

    /** Whether a decision that needed a rate-limited host must block rather than follow fail-open. */
    public boolean failClosed() {
        return properties.failClosed();
    }

    /**
     * End of the suspension of {@code uri}'s host when it is still suspended. A caller about to
     * skip the call because of it reports it through {@link #recordSkipped}.
     */
    public Optional<Instant> suspendedUntil(URI uri) {
        if (!properties.enabled()) {
            return Optional.empty();
        }
        Optional<String> key = hostKey(uri);
        if (key.isEmpty()) {
            return Optional.empty();
        }
        Suspension suspension = suspensions.get(key.get());
        Instant now = clock.instant();
        return suspension != null && suspension.until().isAfter(now) ? Optional.of(suspension.until()) : Optional.empty();
    }

    public void recordSkipped(URI uri, Origin origin) {
        counter(uri, origin, Metrics.OUTCOME_SUSPENDED).increment();
    }

    /**
     * Records a 429 from {@code uri}'s host and suspends it.
     *
     * @param retryAfter the {@code Retry-After} header it sent (seconds or HTTP date), if any
     * @return end of the suspension
     */
    public Instant recordThrottled(URI uri, @Nullable String retryAfter, Origin origin) {
        counter(uri, origin, Metrics.OUTCOME_RESPONSE).increment();
        Instant now = clock.instant();
        Optional<String> key = hostKey(uri);
        if (!properties.enabled() || key.isEmpty()) {
            return now;
        }
        Optional<Duration> requested = parseRetryAfter(retryAfter, now);
        if (!suspensions.containsKey(key.get()) && !makeRoom(now)) {
            LOG.warn("Upstream {} answered 429 but {} hosts are already tracked : not suspended", key.get(), MAX_HOSTS);
            return now;
        }
        boolean[] started = {false};
        Suspension updated = suspensions.compute(key.get(), (host, current) -> {
            // A 429 for a call sent before the suspension started extends it, but is not a new strike.
            boolean ongoing = current != null && current.until().isAfter(now);
            started[0] = !ongoing;
            int strikes = current == null ? 1 : ongoing ? current.strikes() : current.strikes() + 1;
            Instant until = now.plus(delay(requested, strikes));
            return new Suspension(ongoing && current.until().isAfter(until) ? current.until() : until, strikes);
        });
        // Once per suspension : the calls refused meanwhile are only counted.
        if (started[0]) {
            LOG.warn("Upstream {} is rate-limiting the proxy (429 #{}, Retry-After={}) : calls suspended until {}",
                    key.get(), updated.strikes(), retryAfter, updated.until());
        }
        return updated.until();
    }

    /** A 2xx from {@code uri}'s host : once its suspension is over, the backoff starts afresh. */
    public void recordSuccess(URI uri) {
        if (suspensions.isEmpty()) {
            return;
        }
        hostKey(uri).ifPresent(key -> {
            Instant now = clock.instant();
            Suspension removed = suspensions.computeIfPresent(key,
                    (host, current) -> current.until().isAfter(now) ? current : null);
            if (removed == null) {
                LOG.debug("Upstream {} answers again, backoff reset", key);
            }
        });
    }

    /**
     * Seconds a client should wait before retrying a request that was refused because an upstream
     * is rate-limited : the longest ongoing suspension, or the default backoff when none is known.
     */
    public long retryAfterSeconds() {
        Instant now = clock.instant();
        return suspensions.values().stream()
                .map(Suspension::until)
                .filter(until -> until.isAfter(now))
                .max(Instant::compareTo)
                .map(until -> retryAfterSeconds(until))
                .orElse((long) properties.defaultBackoffSeconds());
    }

    /** Whole seconds until {@code until}, rounded up, at least 1 : the value of a Retry-After header. */
    public long retryAfterSeconds(Instant until) {
        long millis = Duration.between(clock.instant(), until).toMillis();
        return Math.max(1, (millis + 999) / 1000);
    }

    /** Forgets every suspension (tests, and an operator who knows the upstream recovered). */
    public void clear() {
        suspensions.clear();
    }

    private Duration delay(Optional<Duration> requested, int strikes) {
        Duration base;
        double jitter;
        if (requested.isPresent()) {
            base = requested.get();
            jitter = random.getAsDouble() * JITTER_RATIO;
        } else {
            long seconds = (long) properties.defaultBackoffSeconds() << Math.min(strikes - 1, 20);
            base = Duration.ofSeconds(seconds);
            jitter = (random.getAsDouble() * 2 - 1) * JITTER_RATIO;
        }
        long millis = (long) (base.toMillis() * (1 + jitter));
        long min = properties.minBackoffSeconds() * 1000L;
        long max = properties.maxBackoffSeconds() * 1000L;
        return Duration.ofMillis(Math.min(max, Math.max(min, millis)));
    }

    // Retry-After is either delay-seconds or an HTTP-date (RFC 9110 10.2.3) ; anything else is ignored.
    static Optional<Duration> parseRetryAfter(@Nullable String value, Instant now) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String trimmed = value.trim();
        if (trimmed.chars().allMatch(Character::isDigit)) {
            try {
                return Optional.of(Duration.ofSeconds(Long.parseLong(trimmed)));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        try {
            Instant date = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            return Optional.of(date.isAfter(now) ? Duration.between(now, date) : Duration.ZERO);
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }

    // Drops the suspensions that are over ; false when the map is still full afterwards.
    private boolean makeRoom(Instant now) {
        if (suspensions.size() < MAX_HOSTS) {
            return true;
        }
        suspensions.values().removeIf(suspension -> !suspension.until().isAfter(now));
        return suspensions.size() < MAX_HOSTS;
    }

    private int suspendedHostCount() {
        Instant now = clock.instant();
        return (int) suspensions.values().stream().filter(suspension -> suspension.until().isAfter(now)).count();
    }

    private Counter counter(URI uri, Origin origin, String outcome) {
        String host = hostKey(uri).filter(knownHosts::contains).orElse(Metrics.HOST_OTHER);
        return Counter.builder(Metrics.UPSTREAM_THROTTLED_METRIC)
                .description("Upstream calls refused with 429, or not sent because the host is suspended")
                .tag(Metrics.TAG_HOST, host)
                .tag(Metrics.TAG_ORIGIN, origin.name())
                .tag(Metrics.TAG_OUTCOME, outcome)
                .register(meterRegistry);
    }

    // host[:port], the port only when it is not the scheme's default.
    static Optional<String> hostKey(URI uri) {
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }
        String key = host.toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        return Optional.of(isDefaultPort(scheme, port) ? key : key + ":" + port);
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return switch (port) {
            case -1 -> true;
            case 443 -> "https".equals(scheme);
            case 80 -> "http".equals(scheme);
            default -> false;
        };
    }
}
