-- Outcome of the HEAD check run before an external validation service is called
-- (services.<name>.head-check). Keyed by the effective URL, so one row serves every
-- service that checks the same artifact, and every instance sharing this database.
--   status : 'EXISTS' | 'NOT_FOUND'  (UNKNOWN is never stored)
-- Rows are deleted by ExternalValidationCleanupService once expires_at has passed.

CREATE TABLE upstream_head_cache (
    url         VARCHAR(2048) PRIMARY KEY,
    status      VARCHAR(20)   NOT NULL,
    checked_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Cleanup scan
CREATE INDEX idx_upstream_head_cache_expires
    ON upstream_head_cache (expires_at);
