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
 * Metric recording for {@link SecurityService}, extracted to its own collaborator so
 * {@code SecurityService} depends on one cohesive bean instead of a raw {@link MeterRegistry}
 * (keeps its constructor parameter list from growing every time a new metric is added there).
 */
@Component
@NullMarked
public class SecurityServiceMetrics {

    private final MeterRegistry meterRegistry;

    public SecurityServiceMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    // Measures cache effectiveness: HIT means decisionDao's single SQL query (company policy,
    // public vulnerability, or api_cache) already resolved the verdict, so no external
    // registry/OSV/deps.dev round trip was needed this request; MISS means one will follow.
    public void recordLocalEvaluationMetric(String outcome) {
        Counter.builder(Metrics.LOCAL_EVALUATION_METRIC)
                .description("Whether a decision was resolved locally (company policy/public vulnerability/api_cache) "
                        + "without needing a registry/OSV/deps.dev external call")
                .tag(Metrics.TAG_OUTCOME, outcome)
                .register(meterRegistry)
                .increment();
    }

    // source is one of the bounded Metrics.DATE_SOURCE_* values : tells how often the quarantine
    // age check ran off the public registry versus a less trusted origin, the local cache, or
    // nothing at all.
    public void recordPublishDateLookup(String ecosystem, String source) {
        Counter.builder(Metrics.PUBLISH_DATE_LOOKUPS_METRIC)
                .description("Publish date resolutions for the quarantine check, by ecosystem and source")
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .tag(Metrics.TAG_SOURCE, source)
                .register(meterRegistry)
                .increment();
    }

    // Alerting target : every increment is a package that skipped the quarantine age check
    // because no publish date could be found, with the verdict applied by quarantine.fail-open.
    public void recordPublishDateUnresolved(String ecosystem, String verdict) {
        Counter.builder(Metrics.PUBLISH_DATE_UNRESOLVED_METRIC)
                .description("Packages whose publish date could not be resolved, by ecosystem and applied verdict")
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .tag(Metrics.TAG_VERDICT, verdict)
                .register(meterRegistry)
                .increment();
    }

    // apiSource/verdict are both bounded enum-like values (OSV_LIVE/DEPS_DEV and
    // ALLOW/BLOCK/ERROR), safe to use as low-cardinality Prometheus tags.
    public void recordExternalApiCallMetric(String apiSource, String result) {
        Counter.builder(Metrics.EXTERNAL_API_CALLS_METRIC)
                .description("Total number of calls to external vulnerability APIs (OSV/deps.dev fallback), by source and result")
                .tag(Metrics.TAG_SOURCE, apiSource)
                .tag(Metrics.TAG_RESULT, result)
                .register(meterRegistry)
                .increment();
    }
}
