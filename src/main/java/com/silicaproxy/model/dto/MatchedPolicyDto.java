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

// A company_policy rule that matches a given package/version, with the result of 
// conflict resolution (specificity + wins). Used by PolicyController for the 
// /evaluate and /simulate endpoints.
@NullMarked
public record MatchedPolicyDto(
    String packageName,
    String versionPattern,
    String policyAction,
    @Nullable String reason,
    int specificity,
    boolean wins
) {}
