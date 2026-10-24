-- Advisories the hourly OSV sync failed to fetch or parse (issue #107). The watermark of the sync
-- moves past them, so without this table they would wait for the nightly zip. Each run retries
-- them first ; a row goes when the advisory succeeds, when a nightly zip of the ecosystem started
-- after its last failure succeeded, or after max-retry-attempts retries.
CREATE TABLE osv_incremental_failed_advisories (
    ecosystem VARCHAR(32) NOT NULL,
    advisory_id TEXT NOT NULL,
    first_failed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_failed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts INT NOT NULL DEFAULT 1,
    last_error TEXT,
    PRIMARY KEY (ecosystem, advisory_id)
);
