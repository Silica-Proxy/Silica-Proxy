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

/**
 * Step of the decision chain that ruled. The first five are produced by the SQL evaluation of
 * {@code DecisionDao} (the names must match its {@code source_type} literals), the others by
 * {@code SecurityService} and {@code ProxyController}. OSV_LIVE/DEPS_DEV are also stored as
 * {@code api_cache.api_source}, as is EXTERNAL_VALIDATION_CHAIN : the api_cache source of an ALLOW
 * reached through the external validation services AND the live fallback chain (never returned
 * as a decision source itself).
 */
public enum DecisionSource {
    COMPANY_POLICY,
    PUBLIC_VULN,
    PUBLIC_VULN_MALWARE,
    PUBLIC_VULN_ANOMALY,
    API_CACHE,
    REGISTRY_NOT_FOUND,
    REGISTRY_ERROR,
    // An upstream needed for the decision is rate-limiting the proxy (429) : temporary, never cached.
    UPSTREAM_THROTTLED,
    REGISTRY_DEPRECATION,
    REGISTRY_QUARANTINE,
    EXTERNAL_VALIDATION,
    // A fail-closed blocking service has no verdict yet because its scan is still running (async
    // callback awaited, or a concurrent sync call for the same package in progress) :
    // temporary (429 + Retry-After), never cached.
    EXTERNAL_VALIDATION_PENDING,
    // A fail-closed blocking service could not give a verdict (sync timeout, network error,
    // unexpected verdict, failed async trigger) : temporary (429 + Retry-After), never cached.
    EXTERNAL_VALIDATION_UNAVAILABLE,
    EXTERNAL_VALIDATION_CHAIN,
    OSV_LIVE,
    DEPS_DEV,
    API_FALLBACK_ERROR,
    DEFAULT,
    UNIDENTIFIED_ARTIFACT
}
