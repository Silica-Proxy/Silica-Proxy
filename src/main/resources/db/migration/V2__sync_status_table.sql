CREATE TABLE sync_status (
    job_id VARCHAR(50) PRIMARY KEY,
    status VARCHAR(20) NOT NULL,
    last_start_time TIMESTAMP WITH TIME ZONE,
    last_end_time TIMESTAMP WITH TIME ZONE,
    duration_ms BIGINT,
    error_message TEXT,
    items_processed BIGINT DEFAULT 0 NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

INSERT INTO sync_status (job_id, status) VALUES ('osv-npm', 'PENDING');
INSERT INTO sync_status (job_id, status) VALUES ('osv-pypi', 'PENDING');
INSERT INTO sync_status (job_id, status) VALUES ('osv-maven', 'PENDING');
INSERT INTO sync_status (job_id, status) VALUES ('ghsa', 'PENDING');
INSERT INTO sync_status (job_id, status) VALUES ('openssf', 'PENDING');
INSERT INTO sync_status (job_id, status) VALUES ('gitlab', 'PENDING');
