-- Synchronization execution history (ZIP batch, git, incremental CSV).
-- Append-only audit table: one row per execution, never truncated.
CREATE TABLE sync_run_history (
    id BIGSERIAL PRIMARY KEY,
    job_id VARCHAR(50) NOT NULL,
    sync_type VARCHAR(30) NOT NULL,                      -- 'OSV_ZIP', 'GIT', 'OSV_INCREMENTAL'
    ecosystem VARCHAR(50),                               -- 'npm', 'pypi', 'maven', etc. (null for multi-ecosystem git)
    source_url TEXT,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ended_at TIMESTAMP WITH TIME ZONE,
    duration_ms BIGINT,
    status VARCHAR(20) NOT NULL,                         -- 'RUNNING', 'SUCCESS', 'FAILED'
    items_discovered BIGINT,                             -- total found in source (ZIP entries, CSV delta lines, git objects)
    items_new BIGINT DEFAULT 0 NOT NULL,                 -- new rows inserted in public_vulnerabilities
    items_updated BIGINT DEFAULT 0 NOT NULL,             -- updated rows (existing)
    items_skipped BIGINT DEFAULT 0 NOT NULL,             -- skipped (already seen, outside watermark window)
    items_failed BIGINT DEFAULT 0 NOT NULL,              -- errors on individual advisories
    watermark_from TIMESTAMP WITH TIME ZONE,             -- incremental only: watermark used as lower bound
    watermark_to TIMESTAMP WITH TIME ZONE,               -- incremental only: watermark recorded at end of cycle
    error_message TEXT
);

CREATE INDEX idx_sync_run_history_job ON sync_run_history (job_id, started_at DESC);
CREATE INDEX idx_sync_run_history_started ON sync_run_history (started_at DESC);

-- Audit of calls to external security APIs (OSV Live, deps.dev).
-- Partitioned by month to contain growth (one call per unknown package).
CREATE TABLE api_call_log (
    id BIGSERIAL,
    called_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    api_source VARCHAR(50) NOT NULL,                     -- 'OSV_LIVE', 'DEPS_DEV'
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    package_version VARCHAR(50) NOT NULL,
    http_status INTEGER,                                 -- HTTP code received (0 if timeout / network error)
    response_time_ms INTEGER,
    verdict VARCHAR(10),                                 -- 'ALLOW', 'BLOCK', 'ERROR'
    vulnerabilities_count INTEGER DEFAULT 0 NOT NULL,
    error_message TEXT,
    PRIMARY KEY (id, called_at)
) PARTITION BY RANGE (called_at);

CREATE TABLE api_call_log_y2026m06 PARTITION OF api_call_log
    FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');

CREATE TABLE api_call_log_y2026m07 PARTITION OF api_call_log
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

CREATE TABLE api_call_log_y2026m08 PARTITION OF api_call_log
    FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');

CREATE INDEX idx_api_call_log_source ON api_call_log (api_source, called_at DESC);
CREATE INDEX idx_api_call_log_package ON api_call_log (package_name, ecosystem, called_at DESC);
