-- One row per (advisory, ecosystem, package) instead of one per advisory: a single OSV
-- advisory routinely affects several packages (GHSA-jfh8-c2jp-5v3q: 4 packages, among which
-- log4j-core). With the PK on id alone, only the last package of the advisory was kept.
ALTER TABLE public_vulnerabilities DROP CONSTRAINT public_vulnerabilities_pkey;
ALTER TABLE public_vulnerabilities ADD PRIMARY KEY (id, ecosystem, package_name);

-- Raw OSV affected[].ranges (SEMVER / ECOSYSTEM only, GIT dropped), evaluated in Java at
-- decision time by OsvRangeEvaluator: [{"type": "SEMVER", "events": [{"introduced": "0"}, ...]}].
-- npm advisories list no version at all in affected[].versions, only these ranges.
-- Constant default : no table rewrite (PostgreSQL 11+), existing rows get '[]' until the next
-- full synchronization fills them.
ALTER TABLE public_vulnerabilities ADD COLUMN affected_ranges JSONB NOT NULL DEFAULT '[]'::jsonb;
