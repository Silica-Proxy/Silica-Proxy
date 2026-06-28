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


package com.silicaproxy.dao.client;

import com.silicaproxy.model.dto.PackageMetadataResult;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import io.micrometer.core.annotation.Timed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves the publication date of a package directly from the public registry (npm, PyPI,
 * Maven Central), and the deprecated/yanked status for npm and PyPI. Called by
 * {@code SecurityService} only when {@code package_metadata} does not already contain the date
 * for this package/version (on-demand resolution, cached locally and permanently 
 * after the first call).
 */
@Component
@NullMarked
public class RegistryClient {

    private static final Logger LOG = LoggerFactory.getLogger(RegistryClient.class);

    private final RestClient restClient;
    private final SilicaProxyProperties properties;

    public RegistryClient(
            SilicaProxyProperties properties,
            @Qualifier("registriesRequestFactory") ClientHttpRequestFactory registriesRequestFactory,
            com.silicaproxy.config.SsrfInterceptor ssrfInterceptor) {
        this.properties = properties;

        this.restClient = RestClient.builder()
                .requestFactory(registriesRequestFactory)
                .requestInterceptor(ssrfInterceptor)
                .build();
    }

    @Timed(value = "silicaproxy.dao.registry.fetchmetadata",
            description = "Duration of call to public registry to resolve package metadata",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<PackageMetadataResult> fetchMetadata(String packageName, String version, String ecosystem) {
        try {
            return switch (ecosystem.toLowerCase()) {
                case "npm" -> fetchNpmMetadata(packageName, version);
                case "pypi" -> fetchPypiMetadata(packageName, version);
                case "maven" -> fetchMavenMetadata(packageName, version);
                default -> Optional.empty();
            };
        } catch (Exception e) {
            LOG.warn("Error while retrieving metadata for {}/{} ({}) : {}", 
                    ecosystem, packageName, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Details of registry metadata retrieval error", e);
            }
            return Optional.empty();
        }
    }

    @SuppressWarnings("unchecked")
    private Optional<PackageMetadataResult> fetchNpmMetadata(String packageName, String version) {
        String url = properties.registries().npmUrl() + "/" + packageName;
        Map<String, Object> response = restClient.get()
                .uri(url)
                .retrieve()
                .body(Map.class);

        if (response == null) {
            return Optional.empty();
        }

        Map<String, String> timeMap = (Map<String, String>) response.get("time");
        if (timeMap == null || !timeMap.containsKey(version)) {
            return Optional.empty();
        }
        Instant publishedAt = Instant.parse(timeMap.get(version));

        Map<String, Object> versionsMap = (Map<String, Object>) response.get("versions");
        boolean isDeprecated = false;
        @Nullable String deprecationReason = null;
        if (versionsMap != null && versionsMap.containsKey(version)) {
            Map<String, Object> versionDetail = (Map<String, Object>) versionsMap.get(version);
            if (versionDetail.containsKey("deprecated")) {
                isDeprecated = true;
                deprecationReason = (String) versionDetail.get("deprecated");
            }
        }

        return Optional.of(new PackageMetadataResult(publishedAt, isDeprecated, deprecationReason));
    }

    @SuppressWarnings("unchecked")
    private Optional<PackageMetadataResult> fetchPypiMetadata(String packageName, String version) {
        String url = properties.registries().pypiUrl() + "/pypi/" + packageName + "/json";
        Map<String, Object> response = restClient.get()
                .uri(url)
                .retrieve()
                .body(Map.class);

        if (response == null) {
            return Optional.empty();
        }

        Map<String, List<Map<String, Object>>> releases = (Map<String, List<Map<String, Object>>>) response.get("releases");
        if (releases == null || !releases.containsKey(version)) {
            return Optional.empty();
        }

        List<Map<String, Object>> files = releases.get(version);
        if (files == null || files.isEmpty()) {
            return Optional.empty();
        }

        Map<String, Object> firstFile = files.get(0);
        String uploadTimeStr = (String) firstFile.get("upload_time_iso_8601");
        if (uploadTimeStr == null) {
            uploadTimeStr = (String) firstFile.get("upload_time");
        }
        if (uploadTimeStr == null) {
            return Optional.empty();
        }
        
        if (!uploadTimeStr.endsWith("Z") && !uploadTimeStr.contains("+")) {
            uploadTimeStr += "Z";
        }
        Instant publishedAt = Instant.parse(uploadTimeStr);

        boolean isYanked = false;
        for (Map<String, Object> file : files) {
            Object yankedObj = file.get("yanked");
            if (yankedObj instanceof Boolean && (Boolean) yankedObj) {
                isYanked = true;
                break;
            }
        }

        return Optional.of(new PackageMetadataResult(
            publishedAt, 
            isYanked, 
            isYanked ? "Yanked from PyPI registry" : null
        ));
    }

    private Optional<PackageMetadataResult> fetchMavenMetadata(String packageName, String version) {
        String[] parts = packageName.split(":");
        String groupIdSlashes = parts[0].replace('.', '/');
        String artifactId = parts.length > 1 ? parts[1] : parts[0];

        String url = properties.registries().mavenUrl() + "/maven2/" + groupIdSlashes + "/" + artifactId + "/" + version + "/";

        ResponseEntity<Void> response = restClient.head()
                .uri(url)
                .retrieve()
                .toBodilessEntity();

        String lastModifiedHeader = response.getHeaders().getFirst("Last-Modified");
        if (lastModifiedHeader == null) {
            return Optional.empty();
        }

        ZonedDateTime zdt = ZonedDateTime.parse(lastModifiedHeader, DateTimeFormatter.RFC_1123_DATE_TIME);
        Instant publishedAt = zdt.toInstant();

        return Optional.of(new PackageMetadataResult(publishedAt, false, null));
    }
}
