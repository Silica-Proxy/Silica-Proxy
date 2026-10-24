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

package com.silicaproxy.controller;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.model.dto.DecisionResult;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Metric recording for {@link ProxyController}, extracted like {@code SecurityServiceMetrics} so
 * the controller depends on one cohesive bean instead of a raw {@link MeterRegistry}.
 */
@Component
@NullMarked
public class ProxyControllerMetrics {

    private final MeterRegistry meterRegistry;
    // Pre-built once at startup (like LoomProxyServer.sslHandshakeTimer) instead of calling
    // Timer.builder(...).register(...) on every request: register() still does a registry
    // lookup under a lock each time, which is unnecessary work on the hot request path.
    private final Timer blockDecisionTimer;
    private final Timer allowDecisionTimer;

    public ProxyControllerMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.blockDecisionTimer = buildSecurityOverheadTimer(meterRegistry, "block");
        this.allowDecisionTimer = buildSecurityOverheadTimer(meterRegistry, "allow");
    }

    private static Timer buildSecurityOverheadTimer(MeterRegistry meterRegistry, String decisionTag) {
        return Timer.builder("silicaproxy.controller.security.overhead")
                .description("Duration of security check only (excluding binary streaming)")
                .tag("decision", decisionTag)
                .publishPercentiles(0.5, 0.9, 0.95, 0.99)
                .register(meterRegistry);
    }

    // sourceType/result/ecosystem are all bounded enum-like values (never raw package names or
    // free-text reasons), so tagging by them stays low-cardinality and safe for Prometheus.
    public void recordDecision(DecisionResult decision, String ecosystem, long executionTimeMs) {
        (decision.isBlocked() ? blockDecisionTimer : allowDecisionTimer).record(Duration.ofMillis(executionTimeMs));
        Counter.builder(Metrics.DECISIONS_METRIC)
                .description("Total number of proxy security decisions, by verdict/source/ecosystem")
                .tag(Metrics.TAG_VERDICT, decision.result().name())
                .tag(Metrics.TAG_SOURCE, decision.sourceType().name())
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .register(meterRegistry)
                .increment();
    }

    // Tracks how much traffic skips SecurityService entirely. Under a known ecosystem this is
    // expected metadata/index traffic ; ecosystem="unknown" is the proxy's security blind spot.
    public void recordBypass(String ecosystem) {
        Counter.builder(Metrics.BYPASS_METRIC)
                .description("Total number of requests that bypassed the security check, by ecosystem "
                        + "(metadata/index traffic under a known ecosystem, blind spot under \"unknown\")")
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .register(meterRegistry)
                .increment();
    }

    public void recordChecksumMismatch(String ecosystem) {
        Counter.builder(Metrics.CHECKSUM_MISMATCH_METRIC)
                .description("Downloads identified from their announced digest whose body did not match it")
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .register(meterRegistry)
                .increment();
    }
}
