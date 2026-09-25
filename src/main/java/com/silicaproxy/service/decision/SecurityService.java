/*
 * Copyright 2026 SilicaProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.silicaproxy.service.decision;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.dao.client.RegistryClient;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.PackageMetadataResult;
import com.silicaproxy.model.dto.RegistryLookup;
import com.silicaproxy.model.entity.SeverityMapping;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import com.silicaproxy.service.vulnerability.VulnerabilityApiClients;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import io.micrometer.core.annotation.Timed;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

/**
 * Central security decision orchestrator  : first evaluates the unique SQL 
 * query from {@code DecisionDao} (policies/vulnerabilities/cache), then, in absence of 
 * result, resolves the package age and deprecation and goes through the fallback chain 
 * (OSV/deps.dev). Called by {@code ProxyController} at each incoming request, 
 * once per resolved package/version/ecosystem.
 */
@Service
@NullMarked
public class SecurityService {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityService.class);

    private final DecisionDao decisionDao;
    private final RegistryClient registryClient;
    private final VulnerabilityApiClients apiClients;
    private final SecurityServiceCaches caches;
    private final SilicaProxyProperties properties;
    private final ExternalValidationService externalValidationService;
    private final SecurityServiceMetrics metrics;
    private final NpmPackumentIndex npmPackumentIndex;

    public SecurityService(
            DecisionDao decisionDao,
            RegistryClient registryClient,
            VulnerabilityApiClients apiClients,
            SecurityServiceCaches caches,
            SilicaProxyProperties properties,
            ExternalValidationService externalValidationService,
            SecurityServiceMetrics metrics,
            NpmPackumentIndex npmPackumentIndex) {
        this.decisionDao = decisionDao;
        this.registryClient = registryClient;
        this.apiClients = apiClients;
        this.caches = caches;
        this.properties = properties;
        this.externalValidationService = externalValidationService;
        this.metrics = metrics;
        this.npmPackumentIndex = npmPackumentIndex;
    }

    @Timed(value = "silicaproxy.service.security.getdecision",
            description = "Duration of security decision evaluation by SecurityService",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public DecisionResult getDecision(
            String packageName, String version, String ecosystem, String fullUrl) {
        // 1. Elements for calculating the floor CVSS
        double minCvss = computeMinCvss(ecosystem);

        // 2. Priority SQL Evaluation
        Optional<DecisionResult> decisionOpt = decisionDao.evaluateDecision(packageName, version, ecosystem, minCvss);
        metrics.recordLocalEvaluationMetric(decisionOpt.isPresent() ? Metrics.OUTCOME_HIT : Metrics.OUTCOME_MISS);
        if (decisionOpt.isPresent()) {
            return decisionOpt.get();
        }

        // 3. New Package / Missing from local database
        RegistryLookup resolution = resolvePackageMetadata(packageName, version, ecosystem, fullUrl);
        Optional<PackageMetadataResult> metadataOpt = resolution.metadata();
        if (metadataOpt.isEmpty()) {
            return unresolvedPublishDateVerdict(packageName, version, ecosystem, resolution.status());
        }
        PackageMetadataResult metadata = metadataOpt.get();

        Optional<DecisionResult> gatedVerdict =
                checkDeprecationAndQuarantine(packageName, version, ecosystem, metadata);
        if (gatedVerdict.isPresent()) {
            return gatedVerdict.get();
        }

        // External validation services (before OSV/deps.dev — skips OSV when configured)
        Optional<DecisionResult> extResult =
                externalValidationService.checkExternalServices(packageName, version, ecosystem, fullUrl);
        if (extResult.isPresent()) {
            return extResult.get();
        }

        return runFallbackChain(packageName, version, ecosystem, true);
    }

    // Deprecation/yanked status is never persisted (unlike published_at): it must stay fresh, so
    // the registry is consulted here every time regardless of whether the publish date is
    // already cached. Reaching this code already means the SQL evaluation above found no cached
    // verdict in api_cache, so in practice this only happens once per api_cache TTL window (24h
    // for an ALLOW, effectively never again once a BLOCK is cached) -- not on every request for
    // the package. Carries no metadata only when no source could date the version AND no local
    // publish date is cached ; its status then tells "unknown version" (NOT_FOUND) from "registry
    // could not answer" (UNAVAILABLE) for the caller's fail-open/fail-closed decision.
    private RegistryLookup resolvePackageMetadata(
            String packageName, String version, String ecosystem, String fullUrl) {
        RegistryLookup lookup;
        String dateSource = Metrics.DATE_SOURCE_PUBLIC_REGISTRY;
        if ("npm".equals(ecosystem)) {
            lookup = registryClient.lookupNpmPublic(packageName, version);
            // The public registry always wins when it knows the version ; the less trusted
            // relayed packument / origin registry is only consulted when it does NOT (JSR,
            // private scope) -- never when it merely failed to answer, otherwise a registry
            // outage would hand the quarantine date over to whatever packument was relayed.
            if (lookup.status() == RegistryLookup.Status.NOT_FOUND) {
                lookup = resolveNpmMetadataFromOrigin(packageName, version)
                        .map(RegistryLookup::found)
                        .orElseGet(RegistryLookup::notFound);
                dateSource = Metrics.DATE_SOURCE_ORIGIN_REGISTRY;
            }
        } else {
            lookup = registryClient.lookup(packageName, version, ecosystem, fullUrl);
        }
        Optional<PackageMetadataResult> registryMetaOpt = lookup.metadata();
        if (registryMetaOpt.isPresent()) {
            PackageMetadataResult registryMeta = registryMetaOpt.get();
            // Permanent registration in package_metadata (idempotent: no-op if already cached)
            caches.metadataCacheDao().savePackagePublishedAt(packageName, ecosystem, version, registryMeta.publishedAt());
            metrics.recordPublishDateLookup(ecosystem, dateSource);
            return lookup;
        }

        // Registry temporarily unreachable but this package/version's publish date is already
        // known: keep quarantine working off the cached date rather than failing the whole
        // request over a transient registry hiccup for an already-vetted package. Deprecation
        // status is unknown this round and left at its default (not deprecated).
        Optional<PackageMetadataResult> cachedMetaOpt =
                caches.metadataCacheDao().getPackagePublishedAt(packageName, ecosystem, version)
                        .map(publishedAt -> new PackageMetadataResult(publishedAt, false, null));
        metrics.recordPublishDateLookup(ecosystem,
                cachedMetaOpt.isPresent() ? Metrics.DATE_SOURCE_LOCAL_CACHE : Metrics.DATE_SOURCE_UNRESOLVED);
        return cachedMetaOpt.map(RegistryLookup::found).orElse(lookup);
    }

    // The packument the client just resolved from is authoritative for that registry, and for a
    // package absent from the configured public registry (JSR, private scope) it is the ONLY
    // source : without it, the public lookup 404s and the request fails closed as "unreachable".
    // Only called once the public registry answered NOT_FOUND for this package/version.
    // (1) the relayed packument itself, when it carried "time" (JSR does, even abbreviated) ;
    // (2) otherwise the FULL packument re-fetched from that same origin registry -- npm's
    // abbreviated format omits "time" but Verdaccio/Artifactory/Nexus include it in the full one.
    // The configured public registry is skipped here : the caller falls back to it anyway.
    private Optional<PackageMetadataResult> resolveNpmMetadataFromOrigin(String packageName, String version) {
        Optional<PackageMetadataResult> fromIndex = npmPackumentIndex.metadata(packageName, version);
        if (fromIndex.isPresent()) {
            return fromIndex;
        }
        return npmPackumentIndex.originPackumentUrl(packageName, version)
                .filter(origin -> !origin.startsWith(properties.registries().npmUrl()))
                .flatMap(origin -> registryClient.fetchNpmMetadataFrom(origin, version));
    }

    // Never cached : the version may appear on the registry (or the registry recover) any time.
    private DecisionResult unresolvedPublishDateVerdict(
            String packageName, String version, String ecosystem, RegistryLookup.Status status) {
        if (status == RegistryLookup.Status.NOT_FOUND
                && properties.quarantine().unknownVersionAction() == SilicaProxyProperties.UnknownVersionAction.BLOCK) {
            LOG.warn("{}/{} ({}) is unknown to every registry consulted : blocked (unknown-version-action=BLOCK)",
                    ecosystem, packageName, version);
            metrics.recordPublishDateUnresolved(ecosystem, "BLOCK");
            return new DecisionResult("REGISTRY_NOT_FOUND", "BLOCK",
                    "Package version is unknown to the registry, its publication date cannot be verified.");
        }
        boolean failOpen = properties.quarantine().failOpen();
        LOG.warn("Unable to retrieve registry metadata for {}/{} ({}). failOpen={}",
                ecosystem, packageName, version, failOpen);
        metrics.recordPublishDateUnresolved(ecosystem, failOpen ? "ALLOW" : "BLOCK");
        if (!failOpen) {
            return new DecisionResult("REGISTRY_ERROR", "BLOCK", "Public registry is unreachable and proxy is configured in fail-closed.");
        }
        if (properties.quarantine().checkVulnerabilitiesOnRegistryError()) {
            // cacheAllow=false : an ALLOW cached here would short-circuit the quarantine check
            // for the whole TTL once the registry recovers.
            DecisionResult vulnVerdict = runFallbackChain(packageName, version, ecosystem, false);
            if ("BLOCK".equals(vulnVerdict.result())) {
                return vulnVerdict;
            }
        }
        return new DecisionResult("REGISTRY_ERROR", "ALLOW", "Fail open due to public registry unavailability.");
    }

    private Optional<DecisionResult> checkDeprecationAndQuarantine(
            String packageName, String version, String ecosystem, PackageMetadataResult metadata) {
        if (isDeprecationFilteringEnabled(ecosystem) && metadata.isDeprecated()) {
            String reason = metadata.deprecationReason() != null
                    ? metadata.deprecationReason() : "The package is deprecated or removed (yanked).";
            // Verdict in persistent cache with infinite TTL (ex: 9999-12-31)
            Instant infiniteExpiry = Instant.parse("9999-12-31T23:59:59Z");
            caches.metadataCacheDao().saveApiCache(packageName, ecosystem, version, false, "REGISTRY_DEPRECATION", infiniteExpiry);
            return Optional.of(new DecisionResult("REGISTRY_DEPRECATION", "BLOCK", reason));
        }

        if (isQuarantineEnabled(ecosystem)) {
            int minAgeDays = getQuarantineMinAgeDays(ecosystem);
            long ageInDays = ChronoUnit.DAYS.between(metadata.publishedAt(), Instant.now());
            if (ageInDays < minAgeDays) {
                String reason = String.format(
                        "Package %s version %s was published %d days ago"
                        + " (required threshold: %d days). Temporarily blocked by anti-typosquatting quarantine.",
                        packageName, version, ageInDays, minAgeDays);
                return Optional.of(new DecisionResult("REGISTRY_QUARANTINE", "BLOCK", reason));
            }
        }

        return Optional.empty();
    }

    @FunctionalInterface
    private interface VulnerabilityCheck {
        ApiCheckResult check(String packageName, String version, String ecosystem);
    }

    private record FallbackSource(String configKey, String apiSource, String providerLabel, VulnerabilityCheck check) {}

    private List<FallbackSource> fallbackSources() {
        return List.of(
                new FallbackSource("osv", Metrics.OSV_LIVE, "OSV", apiClients.osv()::checkVulnerability),
                new FallbackSource("deps-dev", Metrics.DEPS_DEV, "deps.dev", apiClients.depsDev()::checkVulnerability));
    }

    // External API scan (Fallback Chain) : OSV then deps.dev. The first enabled source that
    // answers successfully concludes the chain ; a source that errors (HTTP failure, network,
    // timeout) hands over to the next enabled one instead of concluding. If every enabled
    // source errored, the per-source fail-open/fail-closed policy decides -- and that error
    // verdict is deliberately NEVER written to api_cache : caching it would keep allowing (or
    // blocking) for the whole TTL after the API recovers, turning a transient outage into a
    // 24h security hole.
    // cacheAllow=false never writes an ALLOW verdict to api_cache (a BLOCK is still cached).
    private DecisionResult runFallbackChain(String packageName, String version, String ecosystem, boolean cacheAllow) {
        boolean anyAttempted = false;
        boolean anyFailClosed = false;

        for (FallbackSource source : fallbackSources()) {
            SilicaProxyProperties.ApiFallbackProperties sourceProps = properties.apiFallback().get(source.configKey());
            if (sourceProps == null || !sourceProps.enabled()) {
                continue;
            }
            ApiCheckResult result = source.check().check(packageName, version, ecosystem);
            logApiCall(source.apiSource(), packageName, ecosystem, version, result);
            if (!result.isError()) {
                return resolveFallbackVerdict(packageName, version, ecosystem, source.apiSource(),
                        source.providerLabel(), result.vulnerable(), cacheAllow);
            }
            anyAttempted = true;
            anyFailClosed |= !sourceProps.failOpen();
            LOG.warn("Fallback API {} failed for {}/{} ({}) : {} — trying next enabled source",
                    source.providerLabel(), ecosystem, packageName, version, result.errorMessage());
        }

        if (anyAttempted) {
            // Most restrictive wins across the attempted sources (same aggregation philosophy
            // as ExternalValidationService) : one fail-closed source is enough to block.
            if (anyFailClosed) {
                return new DecisionResult("API_FALLBACK_ERROR", "BLOCK",
                        "External vulnerability APIs are unreachable and fail-closed is configured.");
            }
            return new DecisionResult("API_FALLBACK_ERROR", "ALLOW",
                    "External vulnerability APIs are unreachable; allowed by fail-open policy (verdict not cached).");
        }

        // If no fallback enabled, authorize by default
        if (cacheAllow && properties.apiCache().cacheAllowVerdict()) {
            Instant expiresAt = Instant.now().plus(properties.apiCache().allowVerdictTtlMinutes(), ChronoUnit.MINUTES);
            caches.metadataCacheDao().saveApiCache(packageName, ecosystem, version, true, "DEFAULT", expiresAt);
        }
        return new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule).");
    }

    private void logApiCall(String apiSource, String packageName, String ecosystem, String version,
            ApiCheckResult result) {
        String verdict = result.isError()
                ? "ERROR"
                : (result.vulnerable() ? "BLOCK" : "ALLOW");
        metrics.recordExternalApiCallMetric(apiSource, verdict);
        apiClients.apiCallLogDao().logCall(apiSource, packageName, ecosystem, version, verdict, result);
    }

    private DecisionResult resolveFallbackVerdict(
            String packageName, String version, String ecosystem, String apiSource, String providerLabel,
            boolean isVulnerable, boolean cacheAllow) {
        boolean isSecure = !isVulnerable;

        // Configurable different TTL for BLOCK and ALLOW (0 = do not cache)
        int ttlMinutes = isSecure
            ? properties.apiCache().allowVerdictTtlMinutes()
            : properties.apiCache().blockVerdictTtlMinutes();

        // Cache the verdict if TTL > 0 (BLOCK always, ALLOW only if configured and TTL > 0)
        if (ttlMinutes > 0 && (!isSecure || cacheAllow && properties.apiCache().cacheAllowVerdict())) {
            Instant expiresAt = Instant.now().plus(ttlMinutes, ChronoUnit.MINUTES);
            caches.metadataCacheDao().saveApiCache(packageName, ecosystem, version, isSecure, apiSource, expiresAt);
        }

        if (isSecure) {
            return new DecisionResult(apiSource, "ALLOW", "Validated via external fallback API " + providerLabel + ".");
        }
        return new DecisionResult(apiSource, "BLOCK", "The package contains a vulnerability reported by external API " + providerLabel + ".");
    }

    private double computeMinCvss(String ecosystem) {
        if (!properties.severityThreshold().enabled()) {
            return 11.0;
        }
        SilicaProxyProperties.EcosystemSeverityProperties ecoProps = properties.severityThreshold().ecosystems().get(ecosystem.toLowerCase());
        double configuredCvss;
        String maxSeverity;
        if (ecoProps != null) {
            configuredCvss = ecoProps.maxAllowedCvss();
            maxSeverity = ecoProps.maxAllowedSeverity();
        } else {
            configuredCvss = properties.severityThreshold().defaultMaxAllowedCvss();
            maxSeverity = properties.severityThreshold().defaultMaxAllowedSeverity();
        }
        double resolvedCvss = getSeverityPlancher(maxSeverity);
        return Math.min(configuredCvss, resolvedCvss);
    }

    private double getSeverityPlancher(String maxAllowedSeverity) {
        String nextSeverity = switch (maxAllowedSeverity.toUpperCase()) {
            case "LOW" -> "MEDIUM";
            case "MEDIUM" -> "HIGH";
            case "HIGH" -> "CRITICAL";
            default -> null;
        };

        if (nextSeverity == null) {
            return 11.0;
        }

        @Nullable SeverityMapping mapping = caches.severityMappingsCache().get(nextSeverity);
        if (mapping != null) {
            return mapping.minCvss();
        }

        return switch (nextSeverity) {
            case "MEDIUM" -> 4.0;
            case "HIGH" -> 7.0;
            case "CRITICAL" -> 9.0;
            default -> 11.0;
        };
    }

    private boolean isDeprecationFilteringEnabled(String ecosystem) {
        if (!properties.deprecation().enabled()) {
            return false;
        }
        Boolean ecoEnabled = properties.deprecation().ecosystems().get(ecosystem.toLowerCase());
        return ecoEnabled != null && ecoEnabled;
    }

    private boolean isQuarantineEnabled(String ecosystem) {
        if (!properties.quarantine().enabled()) {
            return false;
        }
        SilicaProxyProperties.EcosystemQuarantineProperties ecoProps = properties.quarantine().ecosystems().get(ecosystem.toLowerCase());
        // Unknown ecosystem: quarantine is active by default (uses defaultMinAgeDays).
        // A known ecosystem with enabled=false explicitly opts out.
        return ecoProps == null || ecoProps.enabled();
    }

    private int getQuarantineMinAgeDays(String ecosystem) {
        SilicaProxyProperties.EcosystemQuarantineProperties ecoProps = properties.quarantine().ecosystems().get(ecosystem.toLowerCase());
        if (ecoProps != null) {
            return ecoProps.minAgeDays();
        }
        return properties.quarantine().defaultMinAgeDays();
    }
}
