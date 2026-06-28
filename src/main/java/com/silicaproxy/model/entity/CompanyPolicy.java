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


package com.silicaproxy.model.entity;

import org.jspecify.annotations.NullMarked;

// A company governance rule (table company_policies). Produced by 
// GitOpsSyncService from the YAML files of the internal Git repository, at each 
// synchronization cycle ; priority 1 in the DecisionDao decision query.
@NullMarked
public record CompanyPolicy(
    String packageName,
    String ecosystem,
    String versionPattern,
    String policyAction,
    String reason,
    String updatedBy
) {}
