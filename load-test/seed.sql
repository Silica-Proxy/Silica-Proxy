-- Clean up existing data to ensure clean state
TRUNCATE company_policies, public_vulnerabilities, api_cache, package_metadata RESTART IDENTITY CASCADE;

-- Seed 50,000 blacklisted npm company policy rules
INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
SELECT
  'blocked-company-' || i,
  'npm',
  '*',
  'BLACKLIST',
  'Blocked by company governance policy',
  'admin-test'
FROM generate_series(0, 49999) AS i;

-- Seed 10,000 blacklisted PyPI company policy rules
INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
SELECT
  'blocked-pypi-' || i,
  'pypi',
  '*',
  'BLACKLIST',
  'Blocked by company governance policy',
  'admin-test'
FROM generate_series(0, 9999) AS i;

-- Seed 10,000 blacklisted Maven company policy rules
INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
SELECT
  'com.example:blocked-maven-' || i,
  'maven',
  '*',
  'BLACKLIST',
  'Blocked by company governance policy',
  'admin-test'
FROM generate_series(0, 9999) AS i;

-- Whitelist ansi-styles for testing the real streaming path
INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
VALUES ('ansi-styles', 'npm', '5.2.0', 'WHITELIST', 'Allowed for testing streaming performance', 'admin-test');

-- Seed 500,000 npm public vulnerabilities (Standard CVSS, CVSS = 9.5)
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
SELECT
  'GHSA-2026-' || i,
  'GITHUB',
  'blocked-vuln-' || i,
  'npm',
  'Test vulnerability summary ' || i,
  'Test vulnerability details ' || i,
  '["1.0.0"]'::jsonb,
  9.5
FROM generate_series(0, 499999) AS i;

-- Seed 500,000 npm public vulnerabilities (Malicious Packages, CVSS = 0.0)
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
SELECT
  'MAL-2026-' || i,
  'OPENSSF',
  'malicious-pkg-' || i,
  'npm',
  'Test malware summary ' || i,
  'Test malware details ' || i,
  '["1.0.0"]'::jsonb,
  0.0
FROM generate_series(0, 499999) AS i;

-- Seed 50,000 PyPI public vulnerabilities (CVSS = 9.5)
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
SELECT
  'GHSA-PYPI-' || i,
  'GITHUB',
  'blocked-pypi-vuln-' || i,
  'pypi',
  'Test PyPI vulnerability summary ' || i,
  'Test PyPI vulnerability details ' || i,
  '["1.0.0"]'::jsonb,
  9.5
FROM generate_series(0, 49999) AS i;

-- Seed 50,000 Maven public vulnerabilities (CVSS = 9.5)
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
SELECT
  'GHSA-MAVEN-' || i,
  'GITHUB',
  'com.example:blocked-maven-vuln-' || i,
  'maven',
  'Test Maven vulnerability summary ' || i,
  'Test Maven vulnerability details ' || i,
  '["1.0.0"]'::jsonb,
  9.5
FROM generate_series(0, 49999) AS i;

-- Verify database state
SELECT count(*) AS company_policies_count FROM company_policies;
SELECT count(*) AS public_vulnerabilities_count FROM public_vulnerabilities;
