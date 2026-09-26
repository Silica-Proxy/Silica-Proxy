-- File digest → package version, learned from deps.dev by the identification from the upstream
-- response (ResponseIdentificationService). Shared by all instances and looked up before deps.dev.
-- Only identified digests are stored ; a digest always designates the same file, so rows never
-- expire. The primary key is the only index needed.

CREATE TABLE file_digest_index (
    hash_type VARCHAR(10) NOT NULL,          -- 'SHA1' | 'SHA256'
    digest VARCHAR(64) NOT NULL,             -- lower-case hex
    ecosystem VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(255) NOT NULL,
    indexed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (hash_type, digest)
);
