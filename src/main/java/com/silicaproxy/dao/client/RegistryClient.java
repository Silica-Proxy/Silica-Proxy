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
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
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
    private final ObjectMapper objectMapper;

    public RegistryClient(
            SilicaProxyProperties properties,
            @Qualifier("registriesRequestFactory") ClientHttpRequestFactory registriesRequestFactory,
            com.silicaproxy.config.SsrfInterceptor ssrfInterceptor,
            ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;

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

    // A full npm packument lists every published version of a package (dependency graphs,
    // dist info, etc. per version) and can reach several MB for popular packages with
    // thousands of releases. Only two scalar fields are actually needed here --
    // time.{version} and versions.{version}.deprecated -- and npm's registry has no cheaper
    // endpoint that carries the exact publish timestamp (neither the abbreviated packument
    // format nor the per-version endpoint GET /{package}/{version} include it; the latter's
    // Last-Modified header reflects CDN cache freshness, not the publish date, and would
    // silently break the anti-typosquatting quarantine age check). So the response is parsed
    // token-by-token instead of deserialized into a generic Map: unwanted version entries are
    // skipped via skipChildren() without allocating any object graph for them.
    private Optional<PackageMetadataResult> fetchNpmMetadata(String packageName, String version) {
        String url = properties.registries().npmUrl() + "/" + packageName;
        return restClient.get()
                .uri(url)
                .exchange((request, response) -> {
                    if (!response.getStatusCode().is2xxSuccessful()) {
                        return Optional.empty();
                    }
                    try (InputStream body = response.getBody()) {
                        return parseNpmPackument(body, version);
                    }
                });
    }

    private Optional<PackageMetadataResult> parseNpmPackument(InputStream body, String version) throws IOException {
        String publishedAtStr = null;
        boolean isDeprecated = false;
        @Nullable String deprecationReason = null;

        try (JsonParser parser = objectMapper.createParser(body)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return Optional.empty();
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String fieldName = parser.currentName();
                JsonToken valueToken = parser.nextToken();
                if ("time".equals(fieldName) && valueToken == JsonToken.START_OBJECT) {
                    publishedAtStr = scanObjectForStringValue(parser, version);
                } else if ("versions".equals(fieldName) && valueToken == JsonToken.START_OBJECT) {
                    DeprecationInfo depInfo = scanVersionsForDeprecation(parser, version);
                    isDeprecated = depInfo.deprecated();
                    deprecationReason = depInfo.reason();
                } else if (valueToken == JsonToken.START_OBJECT || valueToken == JsonToken.START_ARRAY) {
                    parser.skipChildren();
                }
            }
        }

        if (publishedAtStr == null) {
            return Optional.empty();
        }
        return Optional.of(new PackageMetadataResult(Instant.parse(publishedAtStr), isDeprecated, deprecationReason));
    }

    /** Scans the object the parser is currently positioned inside of for a flat string value at {@code key}. */
    private @Nullable String scanObjectForStringValue(JsonParser parser, String key) throws IOException {
        String result = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String currentKey = parser.currentName();
            JsonToken valueToken = parser.nextToken();
            if (currentKey.equals(key) && valueToken == JsonToken.VALUE_STRING) {
                result = parser.getString();
            } else if (valueToken == JsonToken.START_OBJECT || valueToken == JsonToken.START_ARRAY) {
                parser.skipChildren();
            }
        }
        return result;
    }

    private record DeprecationInfo(boolean deprecated, @Nullable String reason) {}

    /** Scans the "versions" object for the matching version entry's "deprecated" field. */
    private DeprecationInfo scanVersionsForDeprecation(JsonParser parser, String version) throws IOException {
        boolean deprecated = false;
        String reason = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String versionKey = parser.currentName();
            JsonToken valueToken = parser.nextToken();
            if (versionKey.equals(version) && valueToken == JsonToken.START_OBJECT) {
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    String innerKey = parser.currentName();
                    JsonToken innerValueToken = parser.nextToken();
                    if ("deprecated".equals(innerKey)) {
                        deprecated = true;
                        if (innerValueToken == JsonToken.VALUE_STRING) {
                            reason = parser.getString();
                        }
                    } else if (innerValueToken == JsonToken.START_OBJECT || innerValueToken == JsonToken.START_ARRAY) {
                        parser.skipChildren();
                    }
                }
            } else if (valueToken == JsonToken.START_OBJECT || valueToken == JsonToken.START_ARRAY) {
                parser.skipChildren();
            }
        }
        return new DeprecationInfo(deprecated, reason);
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
