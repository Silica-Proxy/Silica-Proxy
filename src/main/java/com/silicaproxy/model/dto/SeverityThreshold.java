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

/**
 * Severity threshold of one ecosystem, applied the same way to the local advisories
 * ({@code DecisionDao}) and to the live API findings ({@code SeverityPolicy}). An advisory is
 * blocked when its CVSS score exceeds {@code maxAllowedCvss} (max-allowed-cvss : the configured
 * value itself is allowed) or reaches {@code severityFloor} (the lower bound of the first
 * severity level above max-allowed-severity). A score that is unknown blocks when
 * {@code blockUnknown}. Malware is always blocked and is not this record's concern.
 *
 * @param maxAllowedCvss highest allowed CVSS score, {@link #NO_LIMIT} for none
 * @param severityFloor  lowest blocked CVSS score, {@link #NO_LIMIT} for none
 * @param blockUnknown   whether an advisory with no score at all is blocked
 */
@NullMarked
public record SeverityThreshold(double maxAllowedCvss, double severityFloor, boolean blockUnknown) {

    /** Above any CVSS score (they top out at 10.0) : no limit. */
    public static final double NO_LIMIT = 11.0;

    /** severity-threshold.enabled=false : only malware is blocked. */
    public static SeverityThreshold disabled() {
        return new SeverityThreshold(NO_LIMIT, NO_LIMIT, false);
    }

    /** Blocks from {@code minBlockedScore} on (inclusive), unknown scores allowed. */
    public static SeverityThreshold blockingFrom(double minBlockedScore) {
        return new SeverityThreshold(NO_LIMIT, minBlockedScore, false);
    }

    /** Whether an advisory scored {@code cvssScore} ({@code null} : unknown) is blocked. */
    public boolean blocks(@Nullable Double cvssScore) {
        if (cvssScore == null) {
            return blockUnknown;
        }
        return cvssScore > maxAllowedCvss || cvssScore >= severityFloor;
    }
}
