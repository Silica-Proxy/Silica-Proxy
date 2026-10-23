-- Record who downloaded a package (issue #102), so that an incident can be traced back to the
-- workstations or CI runners affected. Added on the partitioned parent table : PostgreSQL
-- propagates the columns to every existing and future partition. Nullable without default, so
-- the ALTER is a metadata-only change that never rewrites the existing partitions.
ALTER TABLE proxy_audit_logs ADD COLUMN client_ip VARCHAR(64);
ALTER TABLE proxy_audit_logs ADD COLUMN user_agent VARCHAR(512);
-- X-Silica-Client header or Proxy-Authorization username, never the credential itself
ALTER TABLE proxy_audit_logs ADD COLUMN client_id VARCHAR(255);
