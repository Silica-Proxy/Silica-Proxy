-- Optional end date of a company policy, read from the `expires` field of a GitOps rule.
-- NULL means the rule never expires (every rule written before this migration).
-- DecisionDao, GitOpsDao and PackageSearchDao ignore a row once expires_at has passed, so a
-- rule stops applying at its exact end date without waiting for the next GitOps sync ; the
-- sync itself never inserts an already expired rule, so expired rows do not accumulate.

ALTER TABLE company_policies ADD COLUMN expires_at TIMESTAMP WITH TIME ZONE NULL;
