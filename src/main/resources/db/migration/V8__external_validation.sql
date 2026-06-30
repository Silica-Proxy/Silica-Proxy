-- External validation services: two tables for different lifecycle semantics.
--
-- external_validation_cache : transient state
--   - PENDING while external service is thinking (sync or async)
--   - ALLOWED verdicts cached with TTL
--   - TIMEOUT when pending expired without callback
--   Rows are deleted by cleanup scheduler when expires_at <= now()
--
-- external_validation_verdicts : permanent BLOCKED verdicts
--   - Written when a service returns BLOCKED (blocking=true)
--   - No expires_at, no cleanup — permanent record

CREATE TABLE external_validation_cache (
    id              BIGSERIAL    PRIMARY KEY,
    callback_token  UUID,                           -- NULL for sync; non-null for async
    service_name    VARCHAR(100) NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    ecosystem       VARCHAR(50)  NOT NULL,
    package_version VARCHAR(50)  NOT NULL,
    mode            VARCHAR(10)  NOT NULL,           -- 'SYNC' | 'ASYNC'
    status          VARCHAR(20)  NOT NULL,           -- 'PENDING' | 'ALLOWED' | 'TIMEOUT'
    reason          TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL
);

-- One active entry per (service, package) — upsert on conflict
CREATE UNIQUE INDEX idx_ext_cache_lookup
    ON external_validation_cache (service_name, package_name, ecosystem, package_version);

-- Callback lookup for async mode
CREATE INDEX idx_ext_cache_token
    ON external_validation_cache (callback_token)
    WHERE callback_token IS NOT NULL;

-- Cleanup scan
CREATE INDEX idx_ext_cache_expires
    ON external_validation_cache (expires_at);

CREATE TABLE external_validation_verdicts (
    id              BIGSERIAL    PRIMARY KEY,
    service_name    VARCHAR(100) NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    ecosystem       VARCHAR(50)  NOT NULL,
    package_version VARCHAR(50)  NOT NULL,
    reason          TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Permanent unique verdict per (service, package) — insert once, never overwritten
CREATE UNIQUE INDEX idx_ext_verdicts_lookup
    ON external_validation_verdicts (service_name, package_name, ecosystem, package_version);
