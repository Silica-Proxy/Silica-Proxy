ALTER TABLE sync_status ADD COLUMN next_run_time TIMESTAMP WITH TIME ZONE;

INSERT INTO sync_status (job_id, status) VALUES ('gitops-sync', 'PENDING');
