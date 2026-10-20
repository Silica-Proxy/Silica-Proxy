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

import com.silicaproxy.model.dto.AdvisoryFinding;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.SeverityThreshold;
import com.silicaproxy.model.entity.SeverityMapping;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Severity threshold of each ecosystem ({@code silicaproxy.severity-threshold}), and its
 * application to the advisories reported by the live vulnerability APIs, so that a package is
 * judged the same way whether its advisories come from the local tables or from OSV/deps.dev.
 */
@Component
@NullMarked
public class SeverityPolicy {

    // Severity just above each allowed maximum, with its CVSS floor when severity_mappings lacks it.
    private static final Map<String, Map.Entry<String, Double>> NEXT_SEVERITY = Map.of(
            "LOW", Map.entry("MEDIUM", 4.0),
            "MEDIUM", Map.entry("HIGH", 7.0),
            "HIGH", Map.entry("CRITICAL", 9.0));

    private final SilicaProxyProperties properties;
    private final SeverityMappingsCache severityMappingsCache;

    public SeverityPolicy(SilicaProxyProperties properties, SeverityMappingsCache severityMappingsCache) {
        this.properties = properties;
        this.severityMappingsCache = severityMappingsCache;
    }

    public SeverityThreshold thresholdFor(String ecosystem) {
        SilicaProxyProperties.SeverityThresholdProperties threshold = properties.severityThreshold();
        if (!threshold.enabled()) {
            return SeverityThreshold.disabled();
        }
        SilicaProxyProperties.EcosystemSeverityProperties ecoProps =
                threshold.ecosystems().get(ecosystem.toLowerCase(Locale.ROOT));
        double maxAllowedCvss = ecoProps != null ? ecoProps.maxAllowedCvss() : threshold.defaultMaxAllowedCvss();
        String maxSeverity = ecoProps != null ? ecoProps.maxAllowedSeverity() : threshold.defaultMaxAllowedSeverity();
        return new SeverityThreshold(maxAllowedCvss, severityFloor(maxSeverity),
                threshold.unknownSeverityAction() == SilicaProxyProperties.UnknownSeverityAction.BLOCK);
    }

    /**
     * Applies {@code threshold} to the findings of a successful live API answer : advisories that
     * share an id (a PYSEC advisory and the GHSA advisory of the same flaw, linked by alias or by a
     * common CVE id) are judged together, on the highest score known among them. A group blocks
     * when it holds malware, when that score is over the threshold, or when none of them has a
     * score and unknown severities block. Only the ids of blocking groups are kept. A result
     * without findings (the client reported none) is returned unchanged.
     */
    public ApiCheckResult apply(ApiCheckResult result, SeverityThreshold threshold) {
        if (result.isError() || result.findings().isEmpty()) {
            return result;
        }
        List<String> blockingIds = new ArrayList<>();
        for (List<AdvisoryFinding> group : groupByRelatedIds(result.findings())) {
            if (groupBlocks(group, threshold)) {
                group.forEach(finding -> blockingIds.add(finding.id()));
            }
        }
        return new ApiCheckResult(!blockingIds.isEmpty(), result.vulnerabilitiesCount(), result.httpStatus(),
                result.responseTimeMs(), null, blockingIds, result.findings());
    }

    private static boolean groupBlocks(List<AdvisoryFinding> group, SeverityThreshold threshold) {
        Double maxScore = null;
        for (AdvisoryFinding finding : group) {
            if (finding.isMalware()) {
                return true;
            }
            Double score = finding.cvssScore();
            if (score != null && (maxScore == null || score > maxScore)) {
                maxScore = score;
            }
        }
        return threshold.blocks(maxScore);
    }

    // Union-find over the ids : two findings land in the same group as soon as one id (their own,
    // an alias or an upstream id) is shared, directly or through another finding.
    private static List<List<AdvisoryFinding>> groupByRelatedIds(List<AdvisoryFinding> findings) {
        Map<String, String> parent = new HashMap<>();
        for (AdvisoryFinding finding : findings) {
            for (String related : finding.relatedIds()) {
                union(parent, finding.id(), related);
            }
            find(parent, finding.id());
        }
        Map<String, List<AdvisoryFinding>> groups = new LinkedHashMap<>();
        for (AdvisoryFinding finding : findings) {
            groups.computeIfAbsent(find(parent, finding.id()), root -> new ArrayList<>()).add(finding);
        }
        return List.copyOf(groups.values());
    }

    private static String find(Map<String, String> parent, String id) {
        String root = id;
        String next;
        while (!(next = parent.getOrDefault(root, root)).equals(root)) {
            root = next;
        }
        parent.put(id, root);
        return root;
    }

    private static void union(Map<String, String> parent, String first, String second) {
        String firstRoot = find(parent, first);
        String secondRoot = find(parent, second);
        if (!firstRoot.equals(secondRoot)) {
            parent.put(secondRoot, firstRoot);
        }
    }

    // CVSS floor of the severity just above the allowed one : severity_mappings first, then the
    // built-in default.
    private double severityFloor(String maxAllowedSeverity) {
        Map.Entry<String, Double> next = NEXT_SEVERITY.get(maxAllowedSeverity.toUpperCase(Locale.ROOT));
        if (next == null) {
            return SeverityThreshold.NO_LIMIT;
        }
        @Nullable SeverityMapping mapping = severityMappingsCache.get(next.getKey());
        return mapping != null ? mapping.minCvss() : next.getValue();
    }
}
