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


package com.silicaproxy.controller;

import com.silicaproxy.service.search.PackageSearchService;
import com.silicaproxy.service.search.PackageSearchService.SearchResult;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@RestController
@RequestMapping("/api/packages")
@NullMarked
public class PackageSearchController {

    private static final Logger LOG = LoggerFactory.getLogger(PackageSearchController.class);

    private final PackageSearchService packageSearchService;

    public PackageSearchController(PackageSearchService packageSearchService) {
        this.packageSearchService = packageSearchService;
    }

    @GetMapping("/search")
    public ResponseEntity<?> search(
            @RequestParam String packageName,
            @RequestParam(required = false) @Nullable String ecosystem,
            @RequestParam(required = false) @Nullable String version,
            @RequestParam(required = false) @Nullable String versionRegex) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Package search request : name={}, ecosystem={}, version={}, versionRegex={}",
                    sanitizeLog(packageName), sanitizeLog(ecosystem), sanitizeLog(version), sanitizeLog(versionRegex));
        }

        if (version != null && versionRegex != null) {
            LOG.error("Invalid request : both version and versionRegex specified.");
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Provide either 'version' (exact) or 'versionRegex', not both"));
        }
        if (versionRegex != null) {
            try {
                Pattern.compile(versionRegex);
            } catch (PatternSyntaxException e) {
                LOG.error("Invalid request : versionRegex '{}' is malformed.", sanitizeLog(versionRegex), e);
                return ResponseEntity.badRequest()
                        .body(Map.of("message", "Invalid versionRegex: " + e.getMessage()));
            }
        }

        SearchResult result = packageSearchService.search(packageName, ecosystem, version, versionRegex);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Search completed : {} internal policies, {} public vulnerabilities and {} cache entries found.",
                    result.companyPolicies().size(), result.publicVulnerabilities().size(), result.apiCacheEntries().size());
        }

        return ResponseEntity.ok(result);
    }

    private static String sanitizeLog(String s) {
        return s == null ? null : s.replace('\n', ' ').replace('\r', ' ');
    }
}
