-- Total known volume of a job (OSV advisories to process, GitOps rules, received Git objects),
-- used with items_processed to calculate progress percentage.
ALTER TABLE sync_status ADD COLUMN items_total BIGINT;
