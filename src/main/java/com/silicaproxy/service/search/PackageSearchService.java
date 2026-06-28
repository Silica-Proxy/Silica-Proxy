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
import com.silicaproxy.model.entity.CompanyPolicy;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Orchestrates the diagnostic search of a package in the three local sources (validation
 * of mutually exclusive {@code version}/{@code versionRegex} parameters, SQL delegation to
 * {@code PackageSearchDao}). Called only by {@code PackageSearchController}, on demand 
 * via {@code GET /api/packages/search}.
 */
@Service
@NullMarked
public class PackageSearchService {

    private final PackageSearchDao packageSearchDao;

    public PackageSearchService(PackageSearchDao packageSearchDao) {
        this.packageSearchDao = packageSearchDao;
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
                packageSearchDao.searchPublicVulnerabilities(packageName, ecosystem, exactVersion, versionRegex),
                packageSearchDao.searchApiCache(packageName, ecosystem, exactVersion, versionRegex)
        );
    }
}
