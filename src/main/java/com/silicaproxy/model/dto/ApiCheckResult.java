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

import java.time.Instant;
import java.util.List;

/**
 * Enriched result of a call to an external security API (OSV Live, deps.dev),
 * including timing and vulnerability count for audit in {@code api_call_log}.
 */
@NullMarked
public record ApiCheckResult(
        boolean vulnerable,
        int vulnerabilitiesCount,
        int httpStatus,
        long responseTimeMs,
        @Nullable String errorMessage,
        List<String> vulnerabilityIds,
        // Every advisory the API reported, with its score, for SeverityPolicy to apply the
        // severity threshold to. Empty when the client reports none (vulnerable() is then kept).
        List<AdvisoryFinding> findings) {

    public ApiCheckResult(boolean vulnerable, int vulnerabilitiesCount, int httpStatus, long responseTimeMs,
            @Nullable String errorMessage) {
        this(vulnerable, vulnerabilitiesCount, httpStatus, responseTimeMs, errorMessage, List.of());
    }

    public ApiCheckResult(boolean vulnerable, int vulnerabilitiesCount, int httpStatus, long responseTimeMs,
            @Nullable String errorMessage, List<String> vulnerabilityIds) {
        this(vulnerable, vulnerabilitiesCount, httpStatus, responseTimeMs, errorMessage, vulnerabilityIds, List.of());
    }

    /** Successful answer listing {@code findings}, before any severity threshold is applied. */
    public static ApiCheckResult ofFindings(int httpStatus, long responseTimeMs, List<AdvisoryFinding> findings) {
        return new ApiCheckResult(!findings.isEmpty(), findings.size(), httpStatus, responseTimeMs, null,
                findings.stream().map(AdvisoryFinding::id).toList(), findings);
    }

    // The clients (OsvClient, DepsDevClient) set errorMessage on exactly their two failure
    // paths (HTTP non-2xx and transport exception), and on those paths vulnerable() is a
    // meaningless default false -- callers must check this before trusting vulnerable(),
    // otherwise an API outage silently reads as "not vulnerable".
    public boolean isError() {
        return errorMessage != null;
    }

    /** Failed because the API is rate-limiting the proxy : it answered 429, or is suspended after one. */
    public boolean isThrottled() {
        return isError() && httpStatus == THROTTLED_STATUS;
    }

    public static final int THROTTLED_STATUS = 429;

    /** The call was not sent : {@code host} answered 429 and is suspended until {@code until}. */
    public static ApiCheckResult suspended(String host, Instant until) {
        return new ApiCheckResult(false, 0, THROTTLED_STATUS, 0,
                host + " is rate-limiting the proxy, calls suspended until " + until);
    }
}
