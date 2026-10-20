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


package com.silicaproxy.model.dto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * One advisory reported by a live vulnerability API (OSV, deps.dev) for a package version, before
 * the severity threshold is applied by {@code SeverityPolicy}.
 *
 * @param id         advisory id (GHSA-..., PYSEC-..., MAL-...)
 * @param relatedIds ids the advisory is also known under (aliases, upstream)
 * @param cvssScore  score from {@code AdvisorySeverityScorer}, {@code null} when unknown
 */
@NullMarked
public record AdvisoryFinding(String id, List<String> relatedIds, @Nullable Double cvssScore) {

    public AdvisoryFinding {
        relatedIds = List.copyOf(relatedIds);
    }

    /** Known malware (OSV MAL- ids) : always blocked, whatever the threshold. */
    public boolean isMalware() {
        return id.startsWith("MAL-") || relatedIds.stream().anyMatch(related -> related.startsWith("MAL-"));
    }
}
