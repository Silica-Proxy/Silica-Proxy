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
import com.silicaproxy.model.dto.RegistryLookup;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import io.micrometer.core.annotation.Timed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
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

    public Optional<PackageMetadataResult> fetchMetadata(String packageName, String version, String ecosystem) {
        return fetchMetadata(packageName, version, ecosystem, "");
    }

    public Optional<PackageMetadataResult> fetchMetadata(
            String packageName, String version, String ecosystem, String fullUrl) {
        return lookup(packageName, version, ecosystem, fullUrl).metadata();
    }

    /**
     * Resolves {@code packageName@version} on the public registry of {@code ecosystem}, telling
     * a registry that does not know it ({@code NOT_FOUND}) apart from one that could not answer
     * ({@code UNAVAILABLE}). npm only asks the configured public registry here : the origin
     * registry fallback is {@code SecurityService}'s job.
     */
    @Timed(value = "silicaproxy.dao.registry.fetchmetadata",
            description = "Duration of call to public registry to resolve package metadata",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public RegistryLookup lookup(String packageName, String version, String ecosystem, String fullUrl) {
        return switch (ecosystem.toLowerCase(Locale.ROOT)) {
            case "npm" -> lookupNpmPublic(packageName, version);
            case "pypi" -> lookupPypi(packageName, version, fullUrl);
            case "maven" -> lookupMaven(packageName, version, fullUrl);
            default -> RegistryLookup.unavailable();
        };
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
    /**
     * Looks {@code packageName@version} up on the configured public npm registry, telling a
     * registry that does not know the package/version (404, or no {@code time} entry for that
     * version : {@code NOT_FOUND}) apart from one that could not answer (other non-2xx status,
     * network error, timeout, unparseable body : {@code UNAVAILABLE}). {@code SecurityService}
     * only falls back to the less trusted origin registry on {@code NOT_FOUND}.
     */
    @Timed(value = "silicaproxy.dao.registry.lookupnpmpublic",
            description = "Duration of call to the public npm registry to resolve package metadata",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public RegistryLookup lookupNpmPublic(String packageName, String version) {
        String url = properties.registries().npmUrl() + "/" + packageName;
        try {
            return restClient.get()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .exchange((request, response) -> {
                        if (response.getStatusCode().value() == HttpStatus.NOT_FOUND.value()) {
                            return RegistryLookup.notFound();
                        }
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            LOG.warn("Public npm registry answered {} for {} (version {})",
                                    response.getStatusCode().value(), packageName, version);
                            return RegistryLookup.unavailable();
                        }
                        try (InputStream body = response.getBody()) {
                            return parseNpmPackument(body, version)
                                    .map(RegistryLookup::found)
                                    .orElseGet(RegistryLookup::notFound);
                        }
                    });
        } catch (Exception e) {
            LOG.warn("Error while retrieving npm metadata from {} (version {}) : {}", url, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Details of public npm registry lookup error", e);
            }
            return RegistryLookup.unavailable();
        }
    }

    /**
     * Resolves publish date and deprecation status from the packument at {@code packumentUrl},
     * whatever registry serves it. Used by {@code SecurityService} to ask the registry the client
     * actually resolved against (npm.jsr.io, a private Verdaccio/Artifactory…) when the
     * abbreviated packument relayed to the client carried no {@code time} entry -- the package
     * may not exist at all on the configured public registry. The full packument format is
     * requested explicitly : the abbreviated one (npm's default {@code Accept}) omits
     * {@code time}. Goes through the same {@code restClient}, so the SSRF interceptor and the
     * registries timeouts apply.
     */
    @Timed(value = "silicaproxy.dao.registry.fetchnpmmetadatafrom",
            description = "Duration of call to the origin npm registry to resolve package metadata",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<PackageMetadataResult> fetchNpmMetadataFrom(String packumentUrl, String version) {
        try {
            // URI.create, not the String overload : the latter is a URI template and would
            // re-encode the "%2f" of a scoped package name into "%252f".
            return restClient.get()
                    .uri(URI.create(packumentUrl))
                    .header("Accept", "application/json")
                    .exchange((request, response) -> {
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            return Optional.empty();
                        }
                        try (InputStream body = response.getBody()) {
                            return parseNpmPackument(body, version);
                        }
                    });
        } catch (Exception e) {
            LOG.warn("Error while retrieving npm metadata from {} (version {}) : {}", packumentUrl, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Details of npm metadata retrieval error", e);
            }
            return Optional.empty();
        }
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

    /**
     * Looks {@code packageName@version} up on the PyPI JSON API. {@code NOT_FOUND} when PyPI
     * answers 404 or the release is absent / has no file ; {@code UNAVAILABLE} on any other
     * failure, including a response whose shape is not understood (so an API format change
     * follows the fail-open policy instead of looking like "unknown version").
     */
    @SuppressWarnings("unchecked")
    public RegistryLookup lookupPypi(String packageName, String version, String fullUrl) {
        String url = properties.registries().pypiUrl() + "/pypi/" + packageName + "/json";
        try {
            Map<String, Object> response = restClient.get()
                    .uri(url)
                    .retrieve()
                    .body(Map.class);
            return parsePypiRelease(response, version, fullUrl);
        } catch (HttpClientErrorException.NotFound e) {
            return RegistryLookup.notFound();
        } catch (Exception e) {
            LOG.warn("Error while retrieving PyPI metadata for {} ({}) : {}", packageName, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Details of PyPI metadata retrieval error", e);
            }
            return RegistryLookup.unavailable();
        }
    }

    // PyPI lets a maintainer upload new files (wheels for a new platform/Python version) to an
    // existing release long after it was first published : the first file's upload time is
    // therefore NOT the publish date of the file actually being downloaded. The upload time of
    // the requested file (matched by filename) is used ; when it can't be matched, the most
    // recent upload of the release -- the conservative choice for the quarantine age check.
    @SuppressWarnings("unchecked")
    private static RegistryLookup parsePypiRelease(@Nullable Map<String, Object> response, String version, String fullUrl) {
        if (response == null
                || !(response.get("releases") instanceof Map<?, ?> rawReleases)) {
            return RegistryLookup.unavailable();
        }
        Map<String, List<Map<String, Object>>> releases = (Map<String, List<Map<String, Object>>>) rawReleases;
        List<Map<String, Object>> files = releases.get(version);
        if (files == null || files.isEmpty()) {
            return RegistryLookup.notFound();
        }

        Optional<Instant> publishedAtOpt = PypiUploadTimes.publishedAt(files, fullUrl);
        if (publishedAtOpt.isEmpty()) {
            return RegistryLookup.unavailable();
        }
        Instant publishedAt = publishedAtOpt.get();

        boolean isYanked = false;
        for (Map<String, Object> file : files) {
            Object yankedObj = file.get("yanked");
            if (yankedObj instanceof Boolean && (Boolean) yankedObj) {
                isYanked = true;
                break;
            }
        }

        return RegistryLookup.found(new PackageMetadataResult(
            publishedAt,
            isYanked,
            isYanked ? "Yanked from PyPI registry" : null
        ));
    }

    /**
     * Resolves the publish date of a Maven artifact from the {@code Last-Modified} header of its
     * version directory on Maven Central, falling back to the URL the client actually requested.
     * {@code NOT_FOUND} only when every attempted URL answered 404.
     */
    public RegistryLookup lookupMaven(String packageName, String version, String fullUrl) {
        String[] parts = packageName.split(":");
        String groupIdSlashes = parts[0].replace('.', '/');
        String artifactId = parts.length > 1 ? parts[1] : parts[0];

        String url = properties.registries().mavenUrl() + "/maven2/" + groupIdSlashes + "/" + artifactId + "/" + version + "/";

        RegistryLookup central = headLastModified(url);
        if (central.status() == RegistryLookup.Status.FOUND || fullUrl.isBlank()) {
            return central;
        }
        // Maven Central lookup failed (registry down, or artifact not yet mirrored there) --
        // fall back to the exact URL the client requested through the proxy. Safe for Maven
        // specifically because Last-Modified is already its primary publish-date source
        // above (unlike npm/PyPI, where the same header on a tarball/CDN URL reflects cache
        // freshness rather than publish date -- see lookupNpmPublic's comment).
        LOG.debug("Maven Central metadata lookup failed for {}/{}, falling back to intercepted URL", packageName, version);
        RegistryLookup intercepted = headLastModified(fullUrl);
        if (intercepted.status() == RegistryLookup.Status.FOUND) {
            return intercepted;
        }
        boolean bothNotFound = central.status() == RegistryLookup.Status.NOT_FOUND
                && intercepted.status() == RegistryLookup.Status.NOT_FOUND;
        return bothNotFound ? RegistryLookup.notFound() : RegistryLookup.unavailable();
    }

    private RegistryLookup headLastModified(String url) {
        try {
            ResponseEntity<Void> response = restClient.head()
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity();

            String lastModifiedHeader = response.getHeaders().getFirst("Last-Modified");
            if (lastModifiedHeader == null) {
                return RegistryLookup.unavailable();
            }

            ZonedDateTime zdt = ZonedDateTime.parse(lastModifiedHeader, DateTimeFormatter.RFC_1123_DATE_TIME);
            return RegistryLookup.found(new PackageMetadataResult(zdt.toInstant(), false, null));
        } catch (HttpClientErrorException.NotFound e) {
            return RegistryLookup.notFound();
        } catch (Exception e) {
            LOG.debug("HEAD request failed for {} : {}", url, e.getMessage());
            return RegistryLookup.unavailable();
        }
    }
}
