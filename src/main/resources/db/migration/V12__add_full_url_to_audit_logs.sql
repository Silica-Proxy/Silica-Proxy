-- Add the intercepted request's full URL to the audit trail for post-hoc investigation.
ALTER TABLE proxy_audit_logs ADD COLUMN full_url TEXT NOT NULL DEFAULT '';
