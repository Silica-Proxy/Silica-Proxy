-- ExternalValidationService.checkExternalServices() looks up ALL verdicts for a given
-- (package_name, ecosystem, package_version) across every configured service, on every
-- single proxied request (the permanent-block short-circuit). The existing unique index
-- idx_ext_verdicts_lookup has service_name as its leftmost column, so it cannot be used
-- for a lookup that doesn't filter on service_name — every such query falls back to a
-- full table scan. This index supports that query pattern directly.

CREATE INDEX idx_ext_verdicts_by_package
    ON external_validation_verdicts (package_name, ecosystem, package_version);
