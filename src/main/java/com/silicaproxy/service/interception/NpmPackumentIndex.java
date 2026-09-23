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


package com.silicaproxy.service.interception;

import com.silicaproxy.model.dto.PackageMetadataResult;
import com.silicaproxy.dao.client.RegistryClient;
import com.silicaproxy.dao.npm.NpmTarballIndexDao;
import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.service.interception.UrlParserService.ParsedPackage;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Learns {@code tarball URL → (package, version)} from the npm packuments the proxy relays, so
 * that the tarball request that follows can be identified whatever the registry's URL layout.
 *
 * <p>The npm client itself never guesses a tarball URL : it reads {@code versions[v].dist.tarball}
 * from the packument and follows it verbatim. The classic {@code /{name}/-/{name}-{version}.tgz}
 * shape is only registry.npmjs.org's convention -- npm.jsr.io serves
 * {@code /~/{rev}/@jsr/{scope}__{name}/{version}.tgz}, Artifactory prefixes its repository key,
 * etc. Indexing the packument the client just received is the one method that works for all of
 * them, and it is exactly what the client does.
 *
 * <p>The same packument is also the authoritative source of the version's publish date
 * ({@code time.{version}}) and deprecation flag : for a package that does not exist on the
 * configured public registry (JSR, private scopes), it is the ONLY source, so
 * {@link #metadata(String, String)} lets {@code SecurityService} consult it before the registry.
 *
 * <p>In-process only (not shared across instances), bounded by a TTL and a hard size cap like
 * {@link HostSslContextCache}. Lookups normalise the scheme to https and lower-case the host so a
 * plain-http request intercepted before {@code convertToHttpsIfNeeded} still matches.
 */
@Component
@NullMarked
public class NpmPackumentIndex {

    private static final Logger LOG = LoggerFactory.getLogger(NpmPackumentIndex.class);

    private final ObjectMapper objectMapper;
    private final NpmPackumentIndexProperties properties;
    private final NpmTarballIndexDao tarballIndexDao;
    // Tarball URL → version ; "name@version" → metadata. Both hold the same entries, so the size
    // cap is checked on the URL map only.
    private final Map<String, IndexedTarball> index = new ConcurrentHashMap<>();
    private final Map<String, IndexedTarball> byPackage = new ConcurrentHashMap<>();

    private record IndexedTarball(
            String packageName,
            String version,
            @Nullable Instant publishedAt,
            boolean deprecated,
            @Nullable String deprecationReason,
            // URL of the packument this entry was learned from ("" when unknown) : lets
            // SecurityService ask THAT registry for the full packument when the abbreviated one
            // relayed here carried no "time" entry.
            String packumentUrl,
            Instant indexedAt) {}

    @Autowired
    public NpmPackumentIndex(ObjectMapper objectMapper, NpmPackumentIndexProperties properties,
            NpmTarballIndexDao tarballIndexDao) {
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.tarballIndexDao = tarballIndexDao;
    }

    /**
     * Kept for callers predating the removal of the index-time packument re-fetch : the index no
     * longer makes any network call, so {@code registryClient} is not used.
     */
    public NpmPackumentIndex(ObjectMapper objectMapper, NpmPackumentIndexProperties properties,
            NpmTarballIndexDao tarballIndexDao, RegistryClient registryClient) {
        this(objectMapper, properties, tarballIndexDao);
    }

    public boolean isEnabled() {
        return properties.enabled();
    }

    public long maxBodyBytes() {
        return properties.maxBodyBytes();
    }

    /**
     * Parses a packument body (optionally gzip/deflate encoded, as relayed from upstream) and
     * remembers every {@code dist.tarball} URL it declares. Never throws : a body that is not a
     * packument (search results, dist-tags, an error page) is simply ignored.
     *
     * @return the number of tarball URLs indexed from this body
     */
    public int indexPackument(byte[] body, @Nullable String contentEncoding) {
        return indexPackument(body, contentEncoding, "");
    }

    /** Same as {@link #indexPackument(byte[], String)}, remembering the URL the packument came from. */
    public int indexPackument(byte[] body, @Nullable String contentEncoding, String packumentUrl) {
        if (!properties.enabled()) {
            return 0;
        }
        try (InputStream in = decode(new ByteArrayInputStream(body), contentEncoding)) {
            JsonNode root = objectMapper.readTree(in);
            JsonNode versions = root.path("versions");
            if (!versions.isObject()) {
                return 0;
            }
            String defaultName = root.path("name").asString("");
            JsonNode time = root.path("time");
            Instant now = Instant.now();
            int indexed = 0;
            for (Map.Entry<String, JsonNode> entry : versions.properties()) {
                JsonNode manifest = entry.getValue();
                String tarball = manifest.path("dist").path("tarball").asString("");
                if (tarball.isEmpty()) {
                    continue;
                }
                String name = manifest.path("name").asString(defaultName);
                String version = manifest.path("version").asString(entry.getKey());
                if (name.isEmpty()) {
                    continue;
                }
                String key = normalize(tarball);
                if (key != null) {
                    // "deprecated" is a free-text message when set (npm CLI convention) ; some
                    // registries emit a boolean instead.
                    JsonNode deprecatedNode = manifest.path("deprecated");
                    boolean deprecated = deprecatedNode.isBoolean() ? deprecatedNode.asBoolean()
                            : deprecatedNode.isString() && !deprecatedNode.asString().isBlank();
                    @Nullable Instant publishedAt = parseInstant(time.path(entry.getKey()).asString(""));
                    @Nullable String deprecationReason = deprecatedNode.isString() ? deprecatedNode.asString() : null;
                    // No network call here when "time" is absent (npm's abbreviated format) : this
                    // runs while the client waits for the packument, once per version. The publish
                    // date is resolved on demand by SecurityService instead, only for the version
                    // actually downloaded (public registry first, then the recorded packumentUrl).
                    IndexedTarball indexedTarball = new IndexedTarball(name, version,
                            publishedAt, deprecated, deprecationReason, packumentUrl, now);
                    index.put(key, indexedTarball);
                    byPackage.put(packageKey(name, version), indexedTarball);
                    
                    // Persist to DB only if we have metadata worth caching across instances.
                    if (publishedAt != null) {
                        Instant expiresAt = now.plus(Duration.ofMinutes(properties.ttlMinutes()));
                        tarballIndexDao.save(key, name, version, publishedAt, deprecated, deprecationReason,
                                packumentUrl, expiresAt);
                    }
                    indexed++;
                }
            }
            evictIfOversized();
            return indexed;
        } catch (IOException | RuntimeException e) {
            // Not a packument, truncated body, unsupported encoding… : nothing to learn.
            LOG.debug("Packument body not indexable : {}", e.toString());
            return 0;
        }
    }

    /** Resolves a tarball request URL learned from a previously relayed packument. */
    public Optional<ParsedPackage> lookup(String url) {
        if (!properties.enabled()) {
            return Optional.empty();
        }
        String key = normalize(url);
        if (key == null) {
            return Optional.empty();
        }
        IndexedTarball hit = index.get(key);
        if (hit == null) {
            // Cache miss on this instance : check shared DB (multi-instance).
            return tarballIndexDao.findByUrl(key)
                    .map(entry -> new ParsedPackage(entry.packageName(), entry.packageVersion(), "npm"));
        }
        return Optional.of(new ParsedPackage(hit.packageName(), hit.version(), "npm"));
    }

    /**
     * Publish date and deprecation status of {@code packageName@version}, as declared by the
     * packument the client actually resolved from. Empty when unknown or when the packument
     * carried no {@code time} entry for that version (some registries omit it).
     * Falls back to DB for multi-instance cache hit.
     */
    public Optional<PackageMetadataResult> metadata(String packageName, String version) {
        if (!properties.enabled()) {
            return Optional.empty();
        }
        IndexedTarball hit = byPackage.get(packageKey(packageName, version));
        if (hit != null && hit.publishedAt() != null) {
            return Optional.of(new PackageMetadataResult(hit.publishedAt(), hit.deprecated(), hit.deprecationReason()));
        }
        // Cache miss : check shared DB.
        return tarballIndexDao.findMetadataByPackage(packageName, version);
    }

    /**
     * URL of the packument {@code packageName@version} was learned from, i.e. the registry the
     * client actually resolved against. Empty when unknown. Checks shared DB for multi-instance.
     */
    public Optional<String> originPackumentUrl(String packageName, String version) {
        if (!properties.enabled()) {
            return Optional.empty();
        }
        IndexedTarball hit = byPackage.get(packageKey(packageName, version));
        if (hit != null && !hit.packumentUrl().isBlank()) {
            return Optional.of(hit.packumentUrl());
        }
        // Cache miss : check shared DB.
        return tarballIndexDao.findPackumentUrl(packageName, version);
    }

    /** Evicts entries indexed more than {@code ttl} ago. Returns the number of entries evicted. */
    public int evictStaleEntries(Duration ttl) {
        Instant cutoff = Instant.now().minus(ttl);
        int sizeBefore = index.size();
        index.entrySet().removeIf(entry -> entry.getValue().indexedAt().isBefore(cutoff));
        byPackage.entrySet().removeIf(entry -> entry.getValue().indexedAt().isBefore(cutoff));
        return sizeBefore - index.size();
    }

    public Duration ttl() {
        return Duration.ofMinutes(properties.ttlMinutes());
    }

    public int size() {
        return index.size();
    }

    private void evictIfOversized() {
        int excess = index.size() - properties.maxEntries();
        if (excess > 0) {
            index.keySet().stream().limit(excess).toList().forEach(key -> {
                IndexedTarball removed = index.remove(key);
                if (removed != null) {
                    byPackage.remove(packageKey(removed.packageName(), removed.version()), removed);
                }
            });
        }
    }

    private static String packageKey(String packageName, String version) {
        return packageName + "@" + version;
    }


    private static @Nullable Instant parseInstant(String value) {
        if (value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static InputStream decode(InputStream in, @Nullable String contentEncoding) throws IOException {
        if (contentEncoding == null || contentEncoding.isBlank() || "identity".equalsIgnoreCase(contentEncoding)) {
            return in;
        }
        String encoding = contentEncoding.trim().toLowerCase(Locale.ROOT);
        return switch (encoding) {
            case "gzip", "x-gzip" -> new GZIPInputStream(in);
            case "deflate" -> new InflaterInputStream(in);
            default -> throw new IOException("Unsupported Content-Encoding : " + contentEncoding);
        };
    }

    // Key = "https://" + lower-cased host [+ ":" non-default port] + raw path [+ "?" raw query].
    // The raw (still percent-encoded) path is kept : npm follows the packument URL byte for byte,
    // so the intercepted request carries the exact same encoding.
    private static @Nullable String normalize(String url) {
        try {
            URI uri = URI.create(url.trim());
            String host = uri.getHost();
            String path = uri.getRawPath();
            if (host == null || path == null) {
                return null;
            }
            StringBuilder key = new StringBuilder("https://").append(host.toLowerCase(Locale.ROOT));
            int port = uri.getPort();
            if (port != -1 && port != 443 && port != 80) {
                key.append(':').append(port);
            }
            key.append(path);
            if (uri.getRawQuery() != null) {
                key.append('?').append(uri.getRawQuery());
            }
            return key.toString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
