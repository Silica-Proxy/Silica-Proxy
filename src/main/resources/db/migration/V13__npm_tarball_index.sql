-- Multi-instance cache for npm tarball identification and metadata from relayed packuments.
-- Shared by all instances via PostgreSQL, persisted for 60 minutes (configurable TTL).
-- Populated when the proxy relays a packument; consulted when a tarball request arrives on
-- another instance and the local NpmPackumentIndex has no entry (cache miss).
--
-- Indexes: on tarball_url (primary lookup), on expires_at (cleanup), on package identity
-- (fallback query if tarball_url is unknown but we have package@version from another signal).

CREATE TABLE npm_tarball_index (
    tarball_url VARCHAR(2048) NOT NULL PRIMARY KEY,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(50) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL DEFAULT 'npm',
    published_at TIMESTAMP WITH TIME ZONE,
    deprecated BOOLEAN DEFAULT FALSE,
    deprecation_reason TEXT,
    -- URL of the packument this entry came from ("" if unknown) : lets
    -- SecurityService query the origin registry for the full packument when needed.
    packument_url VARCHAR(2048) NOT NULL DEFAULT '',
    indexed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    -- Rows older than this are evicted by scheduled cleanup (default 60 min).
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Lookup by tarball URL (most common): the url the client followed from the packument.
CREATE INDEX idx_npm_tarball_url ON npm_tarball_index(tarball_url);

-- Cleanup: evict expired rows by TTL.
CREATE INDEX idx_npm_tarball_expires ON npm_tarball_index(expires_at);

-- Fallback query if tarball_url layout is unknown: find entries by package@version.
CREATE INDEX idx_npm_tarball_package ON npm_tarball_index(package_name, package_version);
