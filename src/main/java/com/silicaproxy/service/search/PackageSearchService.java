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


package com.silicaproxy.service.search;

import com.silicaproxy.dao.policy.PackageSearchDao;
import com.silicaproxy.model.dto.ApiCacheHit;
import com.silicaproxy.model.dto.PublicVulnerabilityHit;
import com.silicaproxy.model.dto.PublicVulnerabilityRow;
import com.silicaproxy.model.entity.CompanyPolicy;
import com.silicaproxy.service.vulnerability.version.OsvRangeEvaluator;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Orchestrates the diagnostic search of a package in the three local sources (validation
 * of mutually exclusive {@code version}/{@code versionRegex} parameters, SQL delegation to
 * {@code PackageSearchDao}). Called only by {@code PackageSearchController}, on demand
 * via {@code GET /api/packages/search}.
 *
 * <p>Public vulnerabilities are filtered by version in Java : range-only advisories (npm/Maven,
 * no enumerated version) are matched by {@link OsvRangeEvaluator}, as at decision time.
 */
@Service
@NullMarked
public class PackageSearchService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PackageSearchService.class);

    private final PackageSearchDao packageSearchDao;
    private final ObjectMapper objectMapper;

    public PackageSearchService(PackageSearchDao packageSearchDao, ObjectMapper objectMapper) {
        this.packageSearchDao = packageSearchDao;
        this.objectMapper = objectMapper;
    }

    public record SearchResult(
            List<CompanyPolicy> companyPolicies,
            List<PublicVulnerabilityHit> publicVulnerabilities,
            List<ApiCacheHit> apiCacheEntries
    ) {
        public SearchResult {
            companyPolicies = Collections.unmodifiableList(new ArrayList<>(companyPolicies));
            publicVulnerabilities = Collections.unmodifiableList(new ArrayList<>(publicVulnerabilities));
            apiCacheEntries = Collections.unmodifiableList(new ArrayList<>(apiCacheEntries));
        }

        public boolean found() {
            return !companyPolicies.isEmpty() || !publicVulnerabilities.isEmpty() || !apiCacheEntries.isEmpty();
        }
    }

    public SearchResult search(
            String packageName,
            @Nullable String ecosystem,
            @Nullable String exactVersion,
            @Nullable String versionRegex) {
        return new SearchResult(
                packageSearchDao.searchCompanyPolicies(packageName, ecosystem, exactVersion, versionRegex),
                searchPublicVulnerabilities(packageName, ecosystem, exactVersion, versionRegex),
                packageSearchDao.searchApiCache(packageName, ecosystem, exactVersion, versionRegex)
        );
    }

    private List<PublicVulnerabilityHit> searchPublicVulnerabilities(
            String packageName, @Nullable String ecosystem, @Nullable String exactVersion, @Nullable String versionRegex) {
        List<PublicVulnerabilityHit> hits = new ArrayList<>();
        // The regex is applied by the DAO (PostgreSQL) : rows and versions are already filtered by it.
        for (PublicVulnerabilityRow row
                : packageSearchDao.findPublicVulnerabilities(packageName, ecosystem, exactVersion, versionRegex)) {
            List<String> versions = new ArrayList<>();
            for (JsonNode version : readJson(row, row.versionsJson(), "affected_versions")) {
                versions.add(version.asString());
            }
            JsonNode ranges = readJson(row, row.rangesJson(), "affected_ranges");
            matchVersions(row.ecosystem(), versions, ranges, exactVersion)
                    .ifPresent(matched -> hits.add(new PublicVulnerabilityHit(
                            row.id(), row.source(), row.packageName(), row.ecosystem(), row.summary(),
                            row.cvssScore(), row.publishedAt(), matched, ranges)));
        }
        return hits;
    }

    // Empty Optional : the advisory is filtered out.
    private static Optional<List<String>> matchVersions(
            String ecosystem, List<String> versions, JsonNode ranges, @Nullable String exactVersion) {
        if (exactVersion != null) {
            boolean affected = versions.contains(exactVersion)
                    || OsvRangeEvaluator.isAffected(ecosystem, exactVersion, ranges);
            return affected ? Optional.of(List.of(exactVersion)) : Optional.empty();
        }
        return Optional.of(versions);
    }

    private JsonNode readJson(PublicVulnerabilityRow row, String json, String column) {
        try {
            return objectMapper.readTree(json);
        } catch (RuntimeException e) {
            LOGGER.warn("Unreadable {} for advisory {} ({}), treated as empty", column, row.id(), row.packageName(), e);
            return objectMapper.createArrayNode();
        }
    }
}
