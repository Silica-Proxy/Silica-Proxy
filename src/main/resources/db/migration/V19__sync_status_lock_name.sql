-- The ShedLock lock each job runs under, written by every startTask : a force-sync only conflicts
-- with the RUNNING jobs of the nightly cycle, not with an hourly OSV run or a GitOps run.
-- Filled here for the existing rows, so that it holds before their next run.
ALTER TABLE sync_status ADD COLUMN lock_name VARCHAR(100);

UPDATE sync_status SET lock_name = 'VulnerabilitySyncScheduler_sync'
WHERE job_id IN ('osv-npm', 'osv-pypi', 'osv-maven', 'ghsa', 'openssf', 'gitlab');
UPDATE sync_status SET lock_name = 'osv-incremental-sync'
WHERE job_id IN ('osv-npm-incremental', 'osv-pypi-incremental', 'osv-maven-incremental');
UPDATE sync_status SET lock_name = 'gitops_sync_lock' WHERE job_id = 'gitops-sync';
