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

package com.silicaproxy.properties;

import jakarta.validation.constraints.Positive;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Tuning of {@link com.silicaproxy.dao.client.UpstreamThrottle} : how long an upstream host that
 * answered 429 is left alone, and what a security decision does when it needed that host. Kept as
 * its own {@code @ConfigurationProperties} record, like {@link ResponseIdentificationProperties}.
 */
@ConfigurationProperties(prefix = "silicaproxy.upstream-throttle")
@Validated
@NullMarked
public record UpstreamThrottleProperties(
    // false : a 429 is handled like any other upstream failure (no suspension, fail-open decides).
    @DefaultValue("true") boolean enabled,
    // A decision that needed a rate-limited host (publish date, OSV, deps.dev digest lookup) :
    // FAIL_CLOSED blocks it (never cached, the client is told to retry later) ; FOLLOW_FAIL_OPEN
    // treats the 429 like an outage, so each source's fail-open setting decides.
    @DefaultValue("FAIL_CLOSED") OnThrottleAction onThrottle,
    // Suspension when the host sent no usable Retry-After, doubled on each consecutive 429.
    @DefaultValue("30") @Positive int defaultBackoffSeconds,
    @DefaultValue("5") @Positive int minBackoffSeconds,
    // Upper bound of any suspension, Retry-After included.
    @DefaultValue("900") @Positive int maxBackoffSeconds
) {
    @ConstructorBinding
    public UpstreamThrottleProperties {
        // canonical constructor, the one bound by Spring
    }

    public static UpstreamThrottleProperties defaults() {
        return new UpstreamThrottleProperties(true, OnThrottleAction.FAIL_CLOSED, 30, 5, 900);
    }

    public boolean failClosed() {
        return enabled && onThrottle == OnThrottleAction.FAIL_CLOSED;
    }

    public enum OnThrottleAction { FAIL_CLOSED, FOLLOW_FAIL_OPEN }
}
