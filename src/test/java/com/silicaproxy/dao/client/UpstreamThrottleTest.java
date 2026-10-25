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
import com.silicaproxy.properties.UpstreamThrottleProperties;
import com.silicaproxy.properties.UpstreamThrottleProperties.OnThrottleAction;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class UpstreamThrottleTest {

    private static final URI CENTRAL = URI.create("https://repo1.maven.org/maven2/org/slf4j/slf4j-api/maven-metadata.xml");
    private static final Instant NOW = Instant.parse("2026-10-25T11:18:30Z");

    private final MutableClock clock = new MutableClock(NOW);
    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    // 0.5 : no jitter on a computed backoff ((0.5 * 2 - 1) * 20 % = 0), +10 % on a Retry-After.
    private double random = 0.5;

    private UpstreamThrottle throttle(UpstreamThrottleProperties properties) {
        return new UpstreamThrottle(properties, Set.of("repo1.maven.org"), meterRegistry, clock, () -> random);
    }

    private UpstreamThrottle throttle() {
        return throttle(UpstreamThrottleProperties.defaults());
    }

    @Test
    void shouldSuspendForTheRetryAfterSecondsPlusPositiveJitter() {
        UpstreamThrottle throttle = throttle();

        Instant until = throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY);

        assertThat(until).isEqualTo(NOW.plusSeconds(66));
        assertThat(throttle.suspendedUntil(CENTRAL)).contains(until);
    }

    @Test
    void shouldNeverShortenTheRetryAfterTheHostAskedFor() {
        random = 0.0;
        UpstreamThrottle throttle = throttle();

        assertThat(throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY)).isEqualTo(NOW.plusSeconds(60));
    }

    @Test
    void shouldReadAnHttpDateRetryAfter() {
        random = 0.0;
        UpstreamThrottle throttle = throttle();

        Instant until = throttle.recordThrottled(CENTRAL, "Sun, 25 Oct 2026 11:20:30 GMT", UpstreamThrottle.Origin.RELAY);

        assertThat(until).isEqualTo(NOW.plusSeconds(120));
    }

    @Test
    void shouldFallBackToTheDefaultBackoffOnAnUnreadableRetryAfter() {
        UpstreamThrottle throttle = throttle();

        assertThat(throttle.recordThrottled(CENTRAL, "soon", UpstreamThrottle.Origin.RELAY)).isEqualTo(NOW.plusSeconds(30));
    }

    @Test
    void shouldDoubleTheBackoffOnEachNewSuspensionAndCapIt() {
        UpstreamThrottle throttle = throttle();
        long[] expected = {30, 60, 120, 240, 480, 900, 900};

        for (long seconds : expected) {
            Instant until = throttle.recordThrottled(CENTRAL, null, UpstreamThrottle.Origin.REGISTRY);
            assertThat(until).isEqualTo(clock.instant().plusSeconds(seconds));
            clock.set(until.plusSeconds(1));
        }
    }

    @Test
    void shouldCapAHostRetryAfterAtTheMaximum() {
        UpstreamThrottle throttle = throttle();

        assertThat(throttle.recordThrottled(CENTRAL, "3600", UpstreamThrottle.Origin.RELAY)).isEqualTo(NOW.plusSeconds(900));
    }

    @Test
    void shouldApplyTheMinimumToATinyRetryAfter() {
        random = 0.0;
        UpstreamThrottle throttle = throttle();

        assertThat(throttle.recordThrottled(CENTRAL, "0", UpstreamThrottle.Origin.RELAY)).isEqualTo(NOW.plusSeconds(5));
    }

    @Test
    void shouldNotCountA429ReceivedDuringTheSuspensionAsANewStrike() {
        UpstreamThrottle throttle = throttle();
        Instant first = throttle.recordThrottled(CENTRAL, null, UpstreamThrottle.Origin.RELAY);

        // A request sent before the suspension started comes back with its own 429.
        clock.set(NOW.plusSeconds(10));
        assertThat(throttle.recordThrottled(CENTRAL, null, UpstreamThrottle.Origin.RELAY)).isEqualTo(first.plusSeconds(10));

        // Over : the next 429 is the second strike, 60 s.
        clock.set(first.plusSeconds(20));
        assertThat(throttle.recordThrottled(CENTRAL, null, UpstreamThrottle.Origin.RELAY))
                .isEqualTo(clock.instant().plusSeconds(60));
    }

    @Test
    void shouldLiftTheSuspensionOnlyOnceItIsOver() {
        UpstreamThrottle throttle = throttle();
        Instant until = throttle.recordThrottled(CENTRAL, null, UpstreamThrottle.Origin.RELAY);

        // A 2xx for a call sent before the 429 does not lift the suspension.
        throttle.recordSuccess(CENTRAL);
        assertThat(throttle.suspendedUntil(CENTRAL)).contains(until);

        clock.set(until.plusSeconds(1));
        assertThat(throttle.suspendedUntil(CENTRAL)).isEmpty();
        throttle.recordSuccess(CENTRAL);

        // Backoff reset : back to 30 s.
        assertThat(throttle.recordThrottled(CENTRAL, null, UpstreamThrottle.Origin.RELAY))
                .isEqualTo(clock.instant().plusSeconds(30));
    }

    @Test
    void shouldSuspendPerHostIgnoringTheDefaultPort() {
        UpstreamThrottle throttle = throttle();
        throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY);

        assertThat(throttle.suspendedUntil(URI.create("https://REPO1.maven.org:443/maven2/other.pom"))).isPresent();
        assertThat(throttle.suspendedUntil(URI.create("https://repo1.maven.org:8443/maven2/other.pom"))).isEmpty();
        assertThat(throttle.suspendedUntil(URI.create("https://registry.npmjs.org/lodash"))).isEmpty();
    }

    @Test
    void shouldNotSuspendAnythingWhenDisabled() {
        UpstreamThrottle throttle = throttle(new UpstreamThrottleProperties(false, OnThrottleAction.FAIL_CLOSED, 30, 5, 900));

        throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY);

        assertThat(throttle.suspendedUntil(CENTRAL)).isEmpty();
        assertThat(throttle.failClosed()).isFalse();
    }

    @Test
    void shouldStopTrackingNewHostsOnceFull() {
        UpstreamThrottle throttle = throttle();
        for (int i = 0; i < UpstreamThrottle.MAX_HOSTS; i++) {
            throttle.recordThrottled(URI.create("https://host" + i + ".example/"), "60", UpstreamThrottle.Origin.RELAY);
        }

        throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY);
        assertThat(throttle.suspendedUntil(CENTRAL)).isEmpty();

        // Once the suspensions are over, they make room.
        clock.set(NOW.plusSeconds(3600));
        throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY);
        assertThat(throttle.suspendedUntil(CENTRAL)).isPresent();
    }

    @Test
    void shouldTellClientsToWaitForTheLongestSuspension() {
        random = 0.0;
        UpstreamThrottle throttle = throttle();
        assertThat(throttle.retryAfterSeconds()).isEqualTo(30);

        throttle.recordThrottled(CENTRAL, "120", UpstreamThrottle.Origin.RELAY);
        throttle.recordThrottled(URI.create("https://api.osv.dev/v1/query"), "40", UpstreamThrottle.Origin.SECURITY_API);
        clock.set(NOW.plusMillis(500));

        assertThat(throttle.retryAfterSeconds()).isEqualTo(120);
    }

    @Test
    void shouldTagUnconfiguredHostsAsOther() {
        UpstreamThrottle throttle = throttle();

        throttle.recordThrottled(CENTRAL, "60", UpstreamThrottle.Origin.RELAY);
        throttle.recordThrottled(URI.create("https://evil.example/x"), "60", UpstreamThrottle.Origin.RELAY);
        throttle.recordSkipped(CENTRAL, UpstreamThrottle.Origin.REGISTRY);

        assertThat(meterRegistry.get(Metrics.UPSTREAM_THROTTLED_METRIC)
                .tags(Metrics.TAG_HOST, "repo1.maven.org", Metrics.TAG_OUTCOME, Metrics.OUTCOME_RESPONSE).counter().count())
                .isEqualTo(1.0);
        assertThat(meterRegistry.get(Metrics.UPSTREAM_THROTTLED_METRIC)
                .tags(Metrics.TAG_HOST, Metrics.HOST_OTHER).counter().count()).isEqualTo(1.0);
        assertThat(meterRegistry.get(Metrics.UPSTREAM_THROTTLED_METRIC)
                .tags(Metrics.TAG_ORIGIN, "REGISTRY", Metrics.TAG_OUTCOME, Metrics.OUTCOME_SUSPENDED).counter().count())
                .isEqualTo(1.0);
        assertThat(meterRegistry.get(Metrics.UPSTREAM_SUSPENDED_HOSTS_METRIC).gauge().value()).isEqualTo(2.0);
    }

    @Test
    void shouldParseRetryAfterFormats() {
        assertThat(UpstreamThrottle.parseRetryAfter("120", NOW)).contains(Duration.ofSeconds(120));
        assertThat(UpstreamThrottle.parseRetryAfter(" 7 ", NOW)).contains(Duration.ofSeconds(7));
        assertThat(UpstreamThrottle.parseRetryAfter("Sun, 25 Oct 2026 11:00:00 GMT", NOW)).contains(Duration.ZERO);
        assertThat(UpstreamThrottle.parseRetryAfter("-5", NOW)).isEmpty();
        assertThat(UpstreamThrottle.parseRetryAfter("", NOW)).isEmpty();
        assertThat(UpstreamThrottle.parseRetryAfter(null, NOW)).isEmpty();
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant now) {
            this.now = now;
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
