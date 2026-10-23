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

// Aggregated verdict of the external validation services. allowCacheableUntil is set only when
// every enabled service gave a definitive ALLOW (no pending scan, no fail-open error) : it is the
// earliest instant at which one of those ALLOWs stops being valid, i.e. how long the final ALLOW
// of the decision chain may be cached in api_cache.
@NullMarked
public record ExternalValidationOutcome(
    DecisionResult decision,
    @Nullable Instant allowCacheableUntil
) {

    public static ExternalValidationOutcome uncacheable(DecisionResult decision) {
        return new ExternalValidationOutcome(decision, null);
    }
}
