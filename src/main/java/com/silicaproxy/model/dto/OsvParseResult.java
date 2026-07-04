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

import java.util.List;
import org.jspecify.annotations.NullMarked;

// Result of VulnerabilityIngestionService.parseOsvJson(): the upsert requests to persist
// into public_vulnerabilities, plus any affected-version entries that were rejected as
// implausible (see VulnerabilityVersionAnomaly).
@NullMarked
public record OsvParseResult(
        List<VulnerabilityUpsertRequest> upserts,
        List<VulnerabilityVersionAnomaly> anomalies
) {}
