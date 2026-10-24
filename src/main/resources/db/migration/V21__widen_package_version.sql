-- Widen the version columns (issue #110) : an npm version may be up to 256 characters long
-- (long prerelease / build metadata), well beyond the former VARCHAR(50). An overlong version made
-- the insert fail : HTTP 500 on the download, the audit row lost, and a whole 500-row api_call_log
-- batch discarded with it.
-- Increasing a VARCHAR length is a metadata-only change in PostgreSQL : no table rewrite and no
-- index rebuild, even on the indexed / primary key columns. On the partitioned tables
-- (proxy_audit_logs, api_call_log) the ALTER on the parent propagates to every partition.
ALTER TABLE api_cache ALTER COLUMN package_version TYPE VARCHAR(256);
ALTER TABLE package_metadata ALTER COLUMN package_version TYPE VARCHAR(256);
ALTER TABLE proxy_audit_logs ALTER COLUMN package_version TYPE VARCHAR(256);
ALTER TABLE api_call_log ALTER COLUMN package_version TYPE VARCHAR(256);
ALTER TABLE external_validation_cache ALTER COLUMN package_version TYPE VARCHAR(256);
ALTER TABLE external_validation_verdicts ALTER COLUMN package_version TYPE VARCHAR(256);
ALTER TABLE npm_tarball_index ALTER COLUMN package_version TYPE VARCHAR(256);

-- A policy for an exact long version must fit as well.
ALTER TABLE company_policies ALTER COLUMN version_pattern TYPE VARCHAR(256);
