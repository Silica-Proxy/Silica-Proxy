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


package com.silicaproxy.config;

import org.jspecify.annotations.NullMarked;

/**
 * Single source of truth for every custom Micrometer metric name, tag key, and tag value used
 * across the proxy (ProxyController, SecurityService, ExternalValidationService,
 * OsvIncrementalSyncService, GitOpsSyncService, and their tests), so a metric's spelling is
 * never duplicated at each call/assertion site.
 */
@NullMarked
public final class Metrics {

    private Metrics() {
    }

    // ---- Shared tag keys, reused across most of the metrics below ----
    public static final String TAG_VERDICT = "verdict";
    public static final String TAG_SOURCE = "source";
    public static final String TAG_ECOSYSTEM = "ecosystem";
    public static final String TAG_RESULT = "result";
    public static final String TAG_SERVICE = "service";
    public static final String TAG_TYPE = "type";
    public static final String TAG_REASON = "reason";
    public static final String TAG_OUTCOME = "outcome";
    public static final String TAG_SYNC_TYPE = "sync_type";

    // ---- ProxyController ----
    public static final String DECISIONS_METRIC = "silicaproxy.controller.decisions";
    public static final String BYPASS_METRIC = "silicaproxy.controller.security.bypass";

    // ---- SecurityService ----
    public static final String EXTERNAL_API_CALLS_METRIC = "silicaproxy.external.api.calls";
    public static final String OSV_LIVE = "OSV_LIVE";
    public static final String DEPS_DEV = "DEPS_DEV";
    public static final String LOCAL_EVALUATION_METRIC = "silicaproxy.decision.local_evaluation";
    public static final String OUTCOME_HIT = "HIT";
    public static final String OUTCOME_MISS = "MISS";

    // ---- ExternalValidationService ----
    public static final String BLOCKED = "BLOCKED";
    public static final String ALLOWED = "ALLOWED";
    public static final String TYPE_SYNC = "sync";
    public static final String TYPE_ASYNC = "async";
    public static final String RESULT_ERROR = "ERROR";
    public static final String RESULT_UNKNOWN_VERDICT = "UNKNOWN_VERDICT";
    public static final String RESULT_TRIGGERED = "TRIGGERED";
    public static final String RESULT_TRIGGER_ERROR = "TRIGGER_ERROR";
    public static final String VALIDATION_CALLS_METRIC = "silicaproxy.external.validation.calls";
    public static final String BLOCK_REASON_METRIC = "silicaproxy.external.validation.block_reason";
    public static final String REASON_VERDICT = "VERDICT";
    public static final String REASON_FAIL_CLOSED = "FAIL_CLOSED";
    public static final String CALLBACK_METRIC = "silicaproxy.external.validation.callback";
    public static final String SERVICE_UNKNOWN = "unknown";

    // ---- OsvIncrementalSyncService ----
    public static final String OSV_SYNC_ADVISORIES_METRIC = "silicaproxy.vulnerability.sync.advisories";
    public static final String OSV_SYNC_RECORDS_METRIC = "silicaproxy.vulnerability.sync.records";
    public static final String OSV_SYNC_FRESHNESS_METRIC = "silicaproxy.vulnerability.sync.seconds_since_last_success";
    public static final String SYNC_TYPE_INCREMENTAL = "incremental";
    public static final String SYNC_TYPE_FULL = "full";
    public static final String OUTCOME_PROCESSED = "PROCESSED";
    public static final String OUTCOME_FAILED = "FAILED";
    public static final String OUTCOME_INSERTED = "INSERTED";
    public static final String OUTCOME_UPDATED = "UPDATED";

    // ---- GitOpsSyncService ----
    public static final String GITOPS_POLICIES_METRIC = "silicaproxy.gitops.sync.policies";
    public static final String GITOPS_RUNS_METRIC = "silicaproxy.gitops.sync.runs";
    public static final String GITOPS_FRESHNESS_METRIC = "silicaproxy.gitops.sync.seconds_since_last_success";
    public static final String OUTCOME_SUCCESS = "SUCCESS";
    public static final String OUTCOME_FAILURE = "FAILURE";
}
