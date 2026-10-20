-- PyPI names normalized as defined by PEP 503 (lower case, runs of '-', '_', '.' -> '-'), the
-- form the proxy now identifies requests with (ParsedPackage) and stores advisories and GitOps
-- rules under. Two spellings of the same name may collapse onto the same unique key : one row is
-- kept (the already-normalized spelling first) and the others are deleted before the rename.
-- Affected data is either rewritten by the next synchronization (advisories, GitOps rules) or a
-- re-fetchable cache, so nothing is lost for good. Safe to run again : a second run finds
-- nothing left to rename.

-- public_vulnerabilities : primary key (id, ecosystem, package_name)
DELETE FROM public_vulnerabilities
WHERE ctid IN (
    SELECT ctid FROM (
        SELECT ctid,
               ROW_NUMBER() OVER (
                   PARTITION BY id, lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))
                   ORDER BY (package_name = lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))) DESC,
                            imported_at DESC
               ) AS rn
        FROM public_vulnerabilities
        WHERE ecosystem = 'pypi'
    ) ranked
    WHERE rn > 1
);
UPDATE public_vulnerabilities
SET package_name = lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))
WHERE ecosystem = 'pypi'
  AND package_name <> lower(regexp_replace(package_name, '[-_.]+', '-', 'g'));

-- vulnerability_ingestion_anomalies : unique (vulnerability_id, package_name, ecosystem, suspicious_version).
-- suspicious_version itself is left untouched : it is matched as a raw cross-ecosystem string.
DELETE FROM vulnerability_ingestion_anomalies
WHERE id IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY vulnerability_id, lower(regexp_replace(package_name, '[-_.]+', '-', 'g')),
                                suspicious_version
                   ORDER BY (package_name = lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))) DESC, id
               ) AS rn
        FROM vulnerability_ingestion_anomalies
        WHERE ecosystem = 'pypi'
    ) ranked
    WHERE rn > 1
);
UPDATE vulnerability_ingestion_anomalies
SET package_name = lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))
WHERE ecosystem = 'pypi'
  AND package_name <> lower(regexp_replace(package_name, '[-_.]+', '-', 'g'));

-- company_policies : unique (package_name, ecosystem, version_pattern). When two spellings
-- collide, the most restrictive rule is kept (anything but ALLOW blocks, see DecisionDao).
-- '*' wildcards are not touched by the normalization.
DELETE FROM company_policies
WHERE id IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY lower(regexp_replace(package_name, '[-_.]+', '-', 'g')), version_pattern
                   ORDER BY (policy_action = 'ALLOW') ASC, id
               ) AS rn
        FROM company_policies
        WHERE ecosystem = 'pypi'
    ) ranked
    WHERE rn > 1
);
UPDATE company_policies
SET package_name = lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))
WHERE ecosystem = 'pypi'
  AND package_name <> lower(regexp_replace(package_name, '[-_.]+', '-', 'g'));

-- package_metadata : permanent publish dates, copied under the normalized name (a date already
-- stored under that name wins ; between old spellings, the earliest), then the old spellings
-- are dropped.
INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
SELECT lower(regexp_replace(package_name, '[-_.]+', '-', 'g')), ecosystem, package_version, MIN(published_at)
FROM package_metadata
WHERE ecosystem = 'pypi'
  AND package_name <> lower(regexp_replace(package_name, '[-_.]+', '-', 'g'))
GROUP BY lower(regexp_replace(package_name, '[-_.]+', '-', 'g')), ecosystem, package_version
ON CONFLICT (package_name, ecosystem, package_version) DO NOTHING;
DELETE FROM package_metadata
WHERE ecosystem = 'pypi'
  AND package_name <> lower(regexp_replace(package_name, '[-_.]+', '-', 'g'));

-- api_cache : verdicts are a re-fetchable cache ; the ones stored under a non-normalized name
-- would never be read again, so they are simply dropped.
DELETE FROM api_cache
WHERE ecosystem = 'pypi'
  AND package_name <> lower(regexp_replace(package_name, '[-_.]+', '-', 'g'));
