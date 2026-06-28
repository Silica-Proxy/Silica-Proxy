-- 1. Internal policies table (Blacklist / Whitelist)
CREATE TABLE company_policies (
    id SERIAL,
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,        -- 'npm', 'maven', 'pypi'
    version_pattern VARCHAR(50) NOT NULL,  -- '4.17.21', '1.x', ou '*' (global)
    policy_action VARCHAR(20) NOT NULL,    -- 'BLACKLIST' ou 'WHITELIST'
    reason TEXT NOT NULL,                  -- Rule reason / Exception justification
    updated_by VARCHAR(100) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
CREATE UNIQUE INDEX idx_company_policies_lookup 
ON company_policies (package_name, ecosystem, version_pattern);

-- 2. Aggregated public vulnerabilities table
CREATE TABLE public_vulnerabilities (
    id VARCHAR(100) PRIMARY KEY,           -- ex: 'GHSA-xxxx-xxxx', 'OSV-xxxx'
    source VARCHAR(50) NOT NULL,           -- 'GITHUB', 'GITLAB', 'OSV', 'OPENSSF'
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    summary TEXT,
    details TEXT,
    affected_versions JSONB NOT NULL,      -- Flat list of affected versions (e.g. ["1.0.0", "1.0.1"], pre-calculated at ingestion by SemVer range resolution)
    cvss_score NUMERIC(3, 1),              -- Numerical CVSS score (e.g. 8.5)
    published_at TIMESTAMP WITH TIME ZONE,
    imported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2b. Severity levels and CVSS scores mapping table
CREATE TABLE severity_mappings (
    severity_level VARCHAR(20) PRIMARY KEY, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    min_cvss NUMERIC(3, 1) NOT NULL,
    max_cvss NUMERIC(3, 1) NOT NULL
);

INSERT INTO severity_mappings (severity_level, min_cvss, max_cvss) VALUES
('LOW', 0.1, 3.9),
('MEDIUM', 4.0, 6.9),
('HIGH', 7.0, 8.9),
('CRITICAL', 9.0, 10.0);

-- Covering Index enabling Index-Only Scan on CVSS score without reading the physical table
CREATE INDEX idx_public_vuln_search ON public_vulnerabilities (package_name, ecosystem) INCLUDE (cvss_score);

-- 3. Cache table for external fallback APIs (Rate Limiting)
CREATE TABLE api_cache (
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    package_version VARCHAR(50) NOT NULL,
    is_secure BOOLEAN NOT NULL,
    api_source VARCHAR(50),                -- 'PHYLUM', 'OSV_LIVE', 'REGISTRY_DEPRECATION'
    scan_details JSONB,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Expires in 24h if safe (is_secure=true), expires infinitely (e.g. 9999-12-31) if blocked for deprecation
    PRIMARY KEY (package_name, ecosystem, package_version)
);

-- Autovacuum tuning to aggressively clean dead records (expired cache debris)
ALTER TABLE api_cache SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_vacuum_threshold = 100
);

-- 3a. Permanent package metadata table (Publication date)
CREATE TABLE package_metadata (
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    package_version VARCHAR(50) NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (package_name, ecosystem, package_version)
);

-- Index to speed up nightly automatic cleanup of expired caches
CREATE INDEX idx_api_cache_expires_at ON api_cache (expires_at);

-- 4. Audit and history table (Partitioned by month on timestamp)
CREATE TABLE proxy_audit_logs (
    id BIGSERIAL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(50) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    decision_source VARCHAR(50) NOT NULL,  -- 'COMPANY_POLICY', 'PUBLIC_VULN', 'API_CACHE', 'LIVE_API'
    verdict VARCHAR(20) NOT NULL,          -- 'ALLOW', 'BLOCK', 'WHITELISTED', 'BLACKLISTED'
    reason TEXT,                           -- CVE ID or internal reason
    execution_time_ms INT NOT NULL,        -- Total proxy processing time (ms)
    PRIMARY KEY (id, timestamp)            -- The partition key must be part of the primary key in PostgreSQL
) PARTITION BY RANGE (timestamp);

-- Example of monthly partition creation (pre-created by Flyway or scheduled task)
CREATE TABLE proxy_audit_logs_y2026m06 PARTITION OF proxy_audit_logs
    FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');

CREATE TABLE proxy_audit_logs_y2026m07 PARTITION OF proxy_audit_logs
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');

CREATE TABLE proxy_audit_logs_y2026m08 PARTITION OF proxy_audit_logs
    FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');

-- Index on parent table (automatically propagated to each partition by PostgreSQL)
CREATE INDEX idx_audit_timestamp ON proxy_audit_logs (timestamp DESC);
CREATE INDEX idx_audit_package ON proxy_audit_logs (package_name, ecosystem);

-- 5. Distributed lock table for multi-instance (ShedLock)
CREATE TABLE shedlock (
    name VARCHAR(64) NOT NULL,
    lock_until TIMESTAMP WITH TIME ZONE NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE NOT NULL,
    locked_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);
