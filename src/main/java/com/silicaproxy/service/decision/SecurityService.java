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
import com.silicaproxy.dao.client.RegistryClient;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.model.dto.PackageMetadataResult;
import com.silicaproxy.model.dto.RegistryLookup;
import com.silicaproxy.model.dto.Verdict;
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
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

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

    // CVSS floor meaning "no severity limit" (CVSS scores top out at 10.0).
    private static final double NO_CVSS_FLOOR = 11.0;
    // Severity just above each allowed maximum, with its CVSS floor when severity_mappings lacks it.
    private static final Map<String, Map.Entry<String, Double>> NEXT_SEVERITY = Map.of(
            "LOW", Map.entry("MEDIUM", 4.0),
            "MEDIUM", Map.entry("HIGH", 7.0),
            "HIGH", Map.entry("CRITICAL", 9.0));

    private final LocalDecisionEvaluator localDecisionEvaluator;
    private final RegistryClient registryClient;
    private final VulnerabilityApiClients apiClients;
    private final SecurityServiceCaches caches;
    private final SilicaProxyProperties properties;
    private final ExternalValidationService externalValidationService;
    private final SecurityServiceMetrics metrics;
    private final NpmPackumentIndex npmPackumentIndex;

    public SecurityService(
            LocalDecisionEvaluator localDecisionEvaluator,
            RegistryClient registryClient,
            VulnerabilityApiClients apiClients,
            SecurityServiceCaches caches,
            SilicaProxyProperties properties,
            ExternalValidationService externalValidationService,
            SecurityServiceMetrics metrics,
            NpmPackumentIndex npmPackumentIndex) {
        this.localDecisionEvaluator = localDecisionEvaluator;
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

        // 2. Priority local evaluation (UNION ALL query, then OSV ranges at the P2 rank)
        Optional<DecisionResult> decisionOpt =
                localDecisionEvaluator.evaluate(packageName, version, ecosystem, minCvss);
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

        // External validation services (before OSV/deps.dev). Only a BLOCK short-circuits the
        // chain : an ALLOW may be a fail-open timeout, a pending async scan or a non-blocking
        // service, none of which vetted the package, so the live vulnerability APIs still run.
        Optional<DecisionResult> extResult =
                externalValidationService.checkExternalServices(packageName, version, ecosystem, fullUrl);
        if (extResult.isPresent() && extResult.get().isBlocked()) {
            return extResult.get();
        }

        // No ALLOW is cached in api_cache while external validation is active : the local
        // evaluation reads api_cache first, so a cached ALLOW would bypass the external
        // services (and ignore a later async BLOCKED callback) until it expires.
        return runFallbackChain(packageName, version, ecosystem, extResult.isEmpty());
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
            metrics.recordPublishDateUnresolved(ecosystem, Verdict.BLOCK.name());
            return DecisionResult.block(DecisionSource.REGISTRY_NOT_FOUND,
                    "Package version is unknown to the registry, its publication date cannot be verified.");
        }
        boolean failOpen = properties.quarantine().failOpen();
        LOG.warn("Unable to retrieve registry metadata for {}/{} ({}). failOpen={}",
                ecosystem, packageName, version, failOpen);
        metrics.recordPublishDateUnresolved(ecosystem, (failOpen ? Verdict.ALLOW : Verdict.BLOCK).name());
        if (!failOpen) {
            return DecisionResult.block(DecisionSource.REGISTRY_ERROR, "Public registry is unreachable and proxy is configured in fail-closed.");
        }
        if (properties.quarantine().checkVulnerabilitiesOnRegistryError()) {
            // cacheAllow=false : an ALLOW cached here would short-circuit the quarantine check
            // for the whole TTL once the registry recovers.
            DecisionResult vulnVerdict = runFallbackChain(packageName, version, ecosystem, false);
            if (vulnVerdict.isBlocked()) {
                return vulnVerdict;
            }
        }
        return DecisionResult.allow(DecisionSource.REGISTRY_ERROR, "Fail open due to public registry unavailability.");
    }

    private Optional<DecisionResult> checkDeprecationAndQuarantine(
            String packageName, String version, String ecosystem, PackageMetadataResult metadata) {
        if (isDeprecationFilteringEnabled(ecosystem) && metadata.isDeprecated()) {
            String reason = metadata.deprecationReason() != null
                    ? metadata.deprecationReason() : "The package is deprecated or removed (yanked).";
            // Verdict in persistent cache with infinite TTL (ex: 9999-12-31)
            Instant infiniteExpiry = Instant.parse("9999-12-31T23:59:59Z");
            caches.metadataCacheDao().saveApiCache(packageName, ecosystem, version, false,
                    DecisionSource.REGISTRY_DEPRECATION.name(), infiniteExpiry);
            return Optional.of(DecisionResult.block(DecisionSource.REGISTRY_DEPRECATION, reason));
        }

        OptionalInt quarantineDays = quarantineMinAgeDays(ecosystem);
        if (quarantineDays.isPresent()) {
            int minAgeDays = quarantineDays.getAsInt();
            long ageInDays = ChronoUnit.DAYS.between(metadata.publishedAt(), Instant.now());
            if (ageInDays < minAgeDays) {
                String reason = String.format(
                        "Package %s version %s was published %d days ago"
                        + " (required threshold: %d days). Temporarily blocked by anti-typosquatting quarantine.",
                        packageName, version, ageInDays, minAgeDays);
                return Optional.of(DecisionResult.block(DecisionSource.REGISTRY_QUARANTINE, reason));
            }
        }

        return Optional.empty();
    }

    @FunctionalInterface
    private interface VulnerabilityCheck {
        ApiCheckResult check(String packageName, String version, String ecosystem);
    }

    private record FallbackSource(String configKey, DecisionSource source, String providerLabel, VulnerabilityCheck check) {}

    private List<FallbackSource> fallbackSources() {
        return List.of(
                new FallbackSource("osv", DecisionSource.OSV_LIVE, "OSV", apiClients.osv()::checkVulnerability),
                new FallbackSource("deps-dev", DecisionSource.DEPS_DEV, "deps.dev", apiClients.depsDev()::checkVulnerability));
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
            logApiCall(source.source().name(), packageName, ecosystem, version, result);
            if (!result.isError()) {
                return resolveFallbackVerdict(packageName, version, ecosystem, source.source(),
                        source.providerLabel(), result, cacheAllow);
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
                return DecisionResult.block(DecisionSource.API_FALLBACK_ERROR,
                        "External vulnerability APIs are unreachable and fail-closed is configured.");
            }
            return DecisionResult.allow(DecisionSource.API_FALLBACK_ERROR,
                    "External vulnerability APIs are unreachable; allowed by fail-open policy (verdict not cached).");
        }

        // If no fallback enabled, authorize by default
        if (cacheAllow && properties.apiCache().cacheAllowVerdict()) {
            Instant expiresAt = Instant.now().plus(properties.apiCache().allowVerdictTtlMinutes(), ChronoUnit.MINUTES);
            caches.metadataCacheDao().saveApiCache(packageName, ecosystem, version, true, DecisionSource.DEFAULT.name(), expiresAt);
        }
        return DecisionResult.allow(DecisionSource.DEFAULT, "Allowed by default (no blocking rule).");
    }

    private void logApiCall(String apiSource, String packageName, String ecosystem, String version,
            ApiCheckResult result) {
        String verdict = result.isError()
                ? "ERROR"
                : (result.vulnerable() ? Verdict.BLOCK : Verdict.ALLOW).name();
        metrics.recordExternalApiCallMetric(apiSource, verdict);
        apiClients.apiCallLogDao().logCall(apiSource, packageName, ecosystem, version, verdict, result);
    }

    private DecisionResult resolveFallbackVerdict(
            String packageName, String version, String ecosystem, DecisionSource source, String providerLabel,
            ApiCheckResult result, boolean cacheAllow) {
        boolean isSecure = !result.vulnerable();

        // Configurable different TTL for BLOCK and ALLOW (0 = do not cache)
        int ttlMinutes = isSecure
            ? properties.apiCache().allowVerdictTtlMinutes()
            : properties.apiCache().blockVerdictTtlMinutes();

        // Cache the verdict if TTL > 0 (BLOCK always, ALLOW only if configured and TTL > 0)
        if (ttlMinutes > 0 && (!isSecure || cacheAllow && properties.apiCache().cacheAllowVerdict())) {
            Instant expiresAt = Instant.now().plus(ttlMinutes, ChronoUnit.MINUTES);
            caches.metadataCacheDao().saveApiCache(packageName, ecosystem, version, isSecure, source.name(), expiresAt,
                    result.vulnerabilityIds());
        }

        if (isSecure) {
            return DecisionResult.allow(source, "Validated via external fallback API " + providerLabel + ".");
        }
        String ids = result.vulnerabilityIds().isEmpty() ? "" : " (" + String.join(", ", result.vulnerabilityIds()) + ")";
        return DecisionResult.block(source,
                "The package contains a vulnerability reported by external API " + providerLabel + ids + ".");
    }

    private double computeMinCvss(String ecosystem) {
        SilicaProxyProperties.SeverityThresholdProperties threshold = properties.severityThreshold();
        if (!threshold.enabled()) {
            return NO_CVSS_FLOOR;
        }
        SilicaProxyProperties.EcosystemSeverityProperties ecoProps = threshold.ecosystems().get(lower(ecosystem));
        double configuredCvss = ecoProps != null ? ecoProps.maxAllowedCvss() : threshold.defaultMaxAllowedCvss();
        String maxSeverity = ecoProps != null ? ecoProps.maxAllowedSeverity() : threshold.defaultMaxAllowedSeverity();
        return Math.min(configuredCvss, severityFloor(maxSeverity));
    }

    // CVSS floor of the severity just above the allowed one : severity_mappings first, then the
    // built-in default.
    private double severityFloor(String maxAllowedSeverity) {
        Map.Entry<String, Double> next = NEXT_SEVERITY.get(maxAllowedSeverity.toUpperCase(Locale.ROOT));
        if (next == null) {
            return NO_CVSS_FLOOR;
        }
        @Nullable SeverityMapping mapping = caches.severityMappingsCache().get(next.getKey());
        return mapping != null ? mapping.minCvss() : next.getValue();
    }

    private boolean isDeprecationFilteringEnabled(String ecosystem) {
        return properties.deprecation().enabled()
                && Boolean.TRUE.equals(properties.deprecation().ecosystems().get(lower(ecosystem)));
    }

    // Empty when quarantine does not apply. An unknown ecosystem is quarantined with
    // defaultMinAgeDays ; a known ecosystem with enabled=false explicitly opts out.
    private OptionalInt quarantineMinAgeDays(String ecosystem) {
        SilicaProxyProperties.QuarantineProperties quarantine = properties.quarantine();
        if (!quarantine.enabled()) {
            return OptionalInt.empty();
        }
        SilicaProxyProperties.EcosystemQuarantineProperties ecoProps = quarantine.ecosystems().get(lower(ecosystem));
        if (ecoProps == null) {
            return OptionalInt.of(quarantine.defaultMinAgeDays());
        }
        return ecoProps.enabled() ? OptionalInt.of(ecoProps.minAgeDays()) : OptionalInt.empty();
    }

    private static String lower(String ecosystem) {
        return ecosystem.toLowerCase(Locale.ROOT);
    }
}
