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

import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Logs, once the application is fully started, every {@link SilicaProxyProperties} value
 * actually bound from configuration (application.yaml plus environment overrides) as an
 * ASCII tree built by {@link ConfigTreePrinter}. The top-level sections (and the
 * {@code apiFallback} sub-tree) are ordered to match the actual package-decision pipeline in
 * {@code com.silicaproxy.service.decision.SecurityService#getDecision} and
 * {@code com.silicaproxy.dao.policy.DecisionDao#evaluateDecision}, not their declaration
 * order in {@link SilicaProxyProperties}, so operators can read the tree top-to-bottom as
 * the sequence of gates a package is actually evaluated against. Sections outside that
 * pipeline (proxy wiring, corporate proxy, TLS, etc.) follow after, in their declared order.
 */
@Component
@NullMarked
public class StartupConfigLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(StartupConfigLogger.class);

    // Mirrors the evaluation sequence of SecurityService#getDecision. Its first call is
    // DecisionDao#evaluateDecision, a single SQL query combining three sources by priority
    // (ORDER BY priority ASC, lowest wins): PRIORITY 1 company_policies (synced from gitops),
    // PRIORITY 2 public_vulnerabilities — NOT solely gated by severityThreshold: a row is
    // matched either if its CVSS clears the severityThreshold-derived floor, OR unconditionally
    // (bypassing that floor) when it is a malware advisory (id LIKE 'MAL-%' or source =
    // 'OPENSSF', see DecisionDao's SQL) — there is no silicaproxy.* property for malware
    // blocking, it is hardcoded and always on. PRIORITY 3 is api_cache. Only if that query
    // finds nothing does SecurityService fall through to deprecation, quarantine, external
    // validation services, then the apiFallback chain, whose verdicts are written back into
    // apiCache.
    private static final List<String> DECISION_ORDER = List.of(
        "gitops",
        "severityThreshold",
        "apiCache",
        "deprecation",
        "quarantine",
        "externalValidation",
        "apiFallback"
    );

    // SecurityService#getDecision queries OSV first and only falls back to deps.dev if OSV
    // is disabled (each enabled source returns a definitive verdict, sequential not parallel).
    private static final List<String> API_FALLBACK_ORDER = List.of("osv", "deps-dev");

    private static final Map<String, List<String>> NODE_ORDERS = Map.of(
        "silicaproxy", DECISION_ORDER,
        "apiFallback", API_FALLBACK_ORDER
    );

    // Display-only rename: the property is still "severityThreshold" in application.yaml
    // and SilicaProxyProperties, but the node in the decision tree is named after what it
    // gates (public-vulnerability filtering by CVSS), since severityThreshold alone
    // undersells it — malware advisories always bypass this threshold (see DECISION_ORDER
    // comment above).
    private static final Map<String, String> NODE_LABELS = Map.of(
        "severityThreshold", "vulnerabilityFiltering"
    );

    private final SilicaProxyProperties properties;

    public StartupConfigLogger(SilicaProxyProperties properties) {
        this.properties = properties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logConfigurationTree() {
        LOGGER.info("Effective configuration loaded at startup:{}{}",
            System.lineSeparator(), ConfigTreePrinter.print("silicaproxy", properties, NODE_ORDERS, NODE_LABELS));
    }
}
