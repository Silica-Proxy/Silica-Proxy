-- Unknown severity and score inheritance through aliases.
--
-- cvss_score becomes NULL when an advisory carries no severity at all (most PYSEC advisories)
-- instead of 0.0, which read as "harmless" and never blocked. Such an advisory inherits the
-- highest score of the advisories it shares an id with (aliases / upstream / common CVE id),
-- computed by VulnerabilityDao.refreshInheritedScores at the end of each sync. The decision
-- compares COALESCE(cvss_score, inherited_cvss_score) with the threshold ; both NULL means
-- "unknown severity", handled by silicaproxy.severity-threshold.unknown-severity-action.
--
-- Rows already stored keep their score, 0.0 included : 0.0 cannot be told apart from a real
-- unknown here, and turning it into NULL would make every such row block at once (default
-- action BLOCK) before its aliases are known. The next full OSV synchronization rewrites every
-- row with its real (possibly NULL) score, its related ids and its inherited score.
-- Constant defaults : no table rewrite (PostgreSQL 11+).
ALTER TABLE public_vulnerabilities ADD COLUMN related_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE public_vulnerabilities ADD COLUMN inherited_cvss_score NUMERIC(3, 1);

ALTER TABLE vulnerability_ingestion_anomalies ALTER COLUMN cvss_score DROP NOT NULL;
ALTER TABLE vulnerability_ingestion_anomalies ALTER COLUMN cvss_score DROP DEFAULT;
