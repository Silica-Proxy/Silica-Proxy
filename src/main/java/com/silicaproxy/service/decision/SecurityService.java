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

import com.silicaproxy.dao.audit.ApiCallLogDao;
import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.dao.policy.MetadataCacheDao;
import com.silicaproxy.dao.client.RegistryClient;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.PackageMetadataResult;
import com.silicaproxy.model.entity.SeverityMapping;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.vulnerability.VulnerabilityApiClients;
import jakarta.annotation.PostConstruct;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import io.micrometer.core.annotation.Timed;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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
    private final MetadataCacheDao metadataCacheDao;
    private final SilicaProxyProperties properties;
    private final ApiCallLogDao apiCallLogDao;
    private final ExternalValidationService externalValidationService;
    private final Map<String, SeverityMapping> severityMappings = new ConcurrentHashMap<>();

    public SecurityService(
            DecisionDao decisionDao,
            RegistryClient registryClient,
            VulnerabilityApiClients apiClients,
            MetadataCacheDao metadataCacheDao,
            SilicaProxyProperties properties,
            ApiCallLogDao apiCallLogDao,
            ExternalValidationService externalValidationService) {
        this.decisionDao = decisionDao;
        this.registryClient = registryClient;
        this.apiClients = apiClients;
        this.metadataCacheDao = metadataCacheDao;
        this.properties = properties;
        this.apiCallLogDao = apiCallLogDao;
        this.externalValidationService = externalValidationService;
    }

    @PostConstruct
    public void init() {
        try {
            for (SeverityMapping mapping : decisionDao.findAllSeverityMappings()) {
                severityMappings.put(mapping.severityLevel().toUpperCase(), mapping);
            }
        } catch (Exception e) {
            LOG.error("Error while loading severity mappings", e);
        }
    }

    @Timed(value = "silicaproxy.service.security.getdecision",
            description = "Duration of security decision evaluation by SecurityService",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public DecisionResult getDecision(String packageName, String version, String ecosystem) {
        // 1. Elements for calculating the floor CVSS
        double minCvss = computeMinCvss(ecosystem);

        // 2. Priority SQL Evaluation
        Optional<DecisionResult> decisionOpt = decisionDao.evaluateDecision(packageName, version, ecosystem, minCvss);
        if (decisionOpt.isPresent()) {
            return decisionOpt.get();
        }

        // 3. New Package / Missing from local database
        // Deprecation/yanked status is never persisted (unlike published_at): it must stay
        // fresh, so the registry is consulted here every time regardless of whether the publish
        // date is already cached. Reaching this code already means step 2 found no cached
        // verdict in api_cache, so in practice this only happens once per api_cache TTL window
        // (24h for an ALLOW, effectively never again once a BLOCK is cached) -- not on every
        // request for the package.
        Optional<Instant> localPublishedAt = metadataCacheDao.getPackagePublishedAt(packageName, ecosystem, version);
        Instant publishedAt;
        boolean isDeprecated = false;
        String deprecationReason = null;

        Optional<PackageMetadataResult> registryMetaOpt = registryClient.fetchMetadata(packageName, version, ecosystem);
        if (registryMetaOpt.isPresent()) {
            PackageMetadataResult registryMeta = registryMetaOpt.get();
            publishedAt = registryMeta.publishedAt();
            isDeprecated = registryMeta.isDeprecated();
            deprecationReason = registryMeta.deprecationReason();

            // Permanent registration in package_metadata (idempotent: no-op if already cached)
            metadataCacheDao.savePackagePublishedAt(packageName, ecosystem, version, publishedAt);
        } else if (localPublishedAt.isPresent()) {
            // Registry temporarily unreachable but this package/version's publish date is
            // already known: keep quarantine working off the cached date rather than failing
            // the whole request over a transient registry hiccup for an already-vetted package.
            // Deprecation status is unknown this round and left at its default (not deprecated).
            publishedAt = localPublishedAt.get();
        } else {
            // Fail-open / fail-closed behavior
            boolean failOpen = properties.quarantine().failOpen();
            LOG.warn("Unable to retrieve registry metadata for {}/{} ({}). failOpen={}",
                    ecosystem, packageName, version, failOpen);
            if (failOpen) {
                return new DecisionResult("REGISTRY_ERROR", "ALLOW", "Fail open due to public registry unavailability.");
            } else {
                return new DecisionResult("REGISTRY_ERROR", "BLOCK", "Public registry is unreachable and proxy is configured in fail-closed.");
            }
        }

        // Deprecation check (only if enabled)
        if (isDeprecationFilteringEnabled(ecosystem) && isDeprecated) {
            String reason = deprecationReason != null ? deprecationReason : "The package is deprecated or removed (yanked).";
            // Verdict in persistent cache with infinite TTL (ex: 9999-12-31)
            Instant infiniteExpiry = Instant.parse("9999-12-31T23:59:59Z");
            metadataCacheDao.saveApiCache(packageName, ecosystem, version, false, "REGISTRY_DEPRECATION", infiniteExpiry);
            return new DecisionResult("REGISTRY_DEPRECATION", "BLOCK", reason);
        }

        // Quarantine check (Anti-Typosquatting)
        if (isQuarantineEnabled(ecosystem)) {
            int minAgeDays = getQuarantineMinAgeDays(ecosystem);
            long ageInDays = ChronoUnit.DAYS.between(publishedAt, Instant.now());
            if (ageInDays < minAgeDays) {
                String reason = String.format(
                        "Package %s version %s was published %d days ago"
                        + " (required threshold: %d days). Temporarily blocked by anti-typosquatting quarantine.",
                        packageName, version, ageInDays, minAgeDays);
                return new DecisionResult("REGISTRY_QUARANTINE", "BLOCK", reason);
            }
        }

        // External validation services (before OSV/deps.dev — skips OSV when configured)
        Optional<DecisionResult> extResult =
                externalValidationService.checkExternalServices(packageName, version, ecosystem);
        if (extResult.isPresent()) {
            return extResult.get();
        }

        // External API scan (Fallback Chain) : OSV, deps.dev, queried sequentially.
        // Only enabled sources are called ; the first enabled source concludes the
        // chain (each call returns a definitive verdict, including in case of network error).
        if (isApiFallbackEnabled("osv")) {
            ApiCheckResult osvResult = apiClients.osv().checkVulnerability(packageName, version, ecosystem);
            logApiCall("OSV_LIVE", packageName, ecosystem, version, osvResult);
            return resolveFallbackVerdict(packageName, version, ecosystem, "OSV_LIVE", "OSV",
                    osvResult.vulnerable());
        }
        if (isApiFallbackEnabled("deps-dev")) {
            ApiCheckResult depsResult = apiClients.depsDev().checkVulnerability(packageName, version, ecosystem);
            logApiCall("DEPS_DEV", packageName, ecosystem, version, depsResult);
            return resolveFallbackVerdict(packageName, version, ecosystem, "DEPS_DEV", "deps.dev",
                    depsResult.vulnerable());
        }

        // If no fallback enabled, authorize by default
        if (properties.apiCache().cacheAllowVerdict()) {
            Instant expiresAt = Instant.now().plus(properties.apiCache().allowVerdictTtlMinutes(), ChronoUnit.MINUTES);
            metadataCacheDao.saveApiCache(packageName, ecosystem, version, true, "DEFAULT", expiresAt);
        }
        return new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule).");
    }

    private void logApiCall(String apiSource, String packageName, String ecosystem, String version,
            ApiCheckResult result) {
        String verdict = (result.errorMessage() != null && result.httpStatus() != 200)
                ? "ERROR"
                : (result.vulnerable() ? "BLOCK" : "ALLOW");
        apiCallLogDao.logCall(apiSource, packageName, ecosystem, version, verdict, result);
    }

    private boolean isApiFallbackEnabled(String sourceKey) {
        SilicaProxyProperties.ApiFallbackProperties sourceProps = properties.apiFallback().get(sourceKey);
        return sourceProps != null && sourceProps.enabled();
    }

    private DecisionResult resolveFallbackVerdict(
            String packageName, String version, String ecosystem, String apiSource, String providerLabel, boolean isVulnerable) {
        boolean isSecure = !isVulnerable;

        // Configurable different TTL for BLOCK and ALLOW (0 = do not cache)
        int ttlMinutes = isSecure
            ? properties.apiCache().allowVerdictTtlMinutes()
            : properties.apiCache().blockVerdictTtlMinutes();

        // Cache the verdict if TTL > 0 (BLOCK always, ALLOW only if configured and TTL > 0)
        if (ttlMinutes > 0 && (!isSecure || properties.apiCache().cacheAllowVerdict())) {
            Instant expiresAt = Instant.now().plus(ttlMinutes, ChronoUnit.MINUTES);
            metadataCacheDao.saveApiCache(packageName, ecosystem, version, isSecure, apiSource, expiresAt);
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

        SeverityMapping mapping = severityMappings.get(nextSeverity);
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
