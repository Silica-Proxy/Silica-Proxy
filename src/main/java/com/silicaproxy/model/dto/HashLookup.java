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

// Outcome of a deps.dev lookup by file digest (DepsDevClient.queryByHash). Like RegistryLookup,
// "deps.dev does not know this file" (NOT_FOUND) is kept apart from "deps.dev could not answer"
// (UNAVAILABLE) : only the former may be cached. AMBIGUOUS : the same digest maps to several
// package versions, none of which can be trusted to be the one downloaded. The coordinates are
// "unknown" unless FOUND ; call carries the HTTP status and timing for api_call_log.
@NullMarked
public record HashLookup(Status status, String ecosystem, String packageName, String version, ApiCheckResult call) {

    private static final String UNKNOWN = "unknown";

    public enum Status { FOUND, NOT_FOUND, AMBIGUOUS, UNAVAILABLE }

    public static HashLookup found(String ecosystem, String packageName, String version, ApiCheckResult call) {
        return new HashLookup(Status.FOUND, ecosystem, packageName, version, call);
    }

    public static HashLookup notFound(ApiCheckResult call) {
        return new HashLookup(Status.NOT_FOUND, UNKNOWN, UNKNOWN, UNKNOWN, call);
    }

    public static HashLookup ambiguous(ApiCheckResult call) {
        return new HashLookup(Status.AMBIGUOUS, UNKNOWN, UNKNOWN, UNKNOWN, call);
    }

    public static HashLookup unavailable(ApiCheckResult call) {
        return new HashLookup(Status.UNAVAILABLE, UNKNOWN, UNKNOWN, UNKNOWN, call);
    }
}
