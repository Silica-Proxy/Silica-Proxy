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
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * Metric recording for {@link ExternalValidationService}, extracted to its own collaborator so
 * {@code ExternalValidationService} depends on one cohesive bean instead of a raw
 * {@link MeterRegistry} directly (keeps its constructor parameter list and import count from
 * growing every time a new metric is added there). Takes plain {@code String} results (never
 * the {@code ExternalValidationService.CallbackResult} enum) so this class has no dependency
 * back on the service it instruments.
 */
@Component
@NullMarked
public class ExternalValidationMetrics {

    private final MeterRegistry meterRegistry;

    public ExternalValidationMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    // serviceName is a fixed set of keys from application config (services.<name>), never
    // user/request-derived, so it stays low-cardinality and safe as a Prometheus tag.
    public void recordExternalValidationCallMetric(String serviceName, String type, String result) {
        Counter.builder(Metrics.VALIDATION_CALLS_METRIC)
                .description("Total number of calls to external validation services, by service name/type/result")
                .tag(Metrics.TAG_SERVICE, serviceName)
                .tag(Metrics.TAG_TYPE, type)
                .tag(Metrics.TAG_RESULT, result)
                .register(meterRegistry)
                .increment();
    }

    public void recordBlockReasonMetric(String reason) {
        Counter.builder(Metrics.BLOCK_REASON_METRIC)
                .description("Total number of packages blocked by external validation, split between a real "
                        + "malicious verdict and a fail-closed block caused by service unavailability")
                .tag(Metrics.TAG_REASON, reason)
                .register(meterRegistry)
                .increment();
    }

    public void recordCallbackMetric(String serviceName, String result) {
        Counter.builder(Metrics.CALLBACK_METRIC)
                .description("Total number of external validation callbacks received, by service and outcome "
                        + "(NOT_FOUND/UNAUTHORIZED surface replay attempts or a misconfigured API key)")
                .tag(Metrics.TAG_SERVICE, serviceName)
                .tag(Metrics.TAG_RESULT, result)
                .register(meterRegistry)
                .increment();
    }
}
