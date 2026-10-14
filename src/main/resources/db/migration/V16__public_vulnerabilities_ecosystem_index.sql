-- DataInventoryService counts public vulnerabilities by ecosystem on every call to
-- GET /api/vulnerabilities/sync/status. Neither idx_public_vuln_search (package_name first)
-- nor the primary key (id first) has ecosystem as its leftmost column, so that GROUP BY
-- ecosystem falls back to a full sequential scan of the table (~280 MB with details /
-- affected_versions / affected_ranges, mostly read from disk : ~4 s in production).
-- This small index allows an Index Only Scan instead.
-- IF NOT EXISTS : the index may already have been created manually on existing instances.

CREATE INDEX IF NOT EXISTS idx_public_vuln_ecosystem
    ON public_vulnerabilities (ecosystem);
