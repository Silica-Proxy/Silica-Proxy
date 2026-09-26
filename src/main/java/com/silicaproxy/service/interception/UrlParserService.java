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

import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import io.micrometer.core.annotation.Timed;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Extracts package/version/ecosystem from the absolute URL intercepted by the proxy (npm,
 * PyPI, Maven paths) ; returns "unknown" parts when the URL does not match any known pattern.
 * Known public registry hosts go to their ecosystem's parser ; any other host goes through the
 * structural fallbacks : npm tarball layouts ({@link NpmUrlParser}), PyPI file names — wheels
 * anywhere, sdists behind a known PyPI prefix ({@link PypiUrlParser}) — and Maven repository
 * layouts ({@link MavenUrlParser}). Client headers are read by {@link #detectNpmMetadata} and
 * {@link #detectClientEcosystem}. Stateless parsing only : the detection layers are chained, and
 * the request classified, by {@link PackageIdentificationService}.
 */
@Service
@NullMarked
public class UrlParserService {

    private record EcosystemRouter(List<String> hostPatterns, Function<String, ParsedPackage> parser) {
        boolean matches(String host) {
            for (String p : hostPatterns) {
                if (host.equals(p) || host.endsWith("." + p)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final List<EcosystemRouter> ROUTERS = List.of(
            new EcosystemRouter(List.of("npmjs.org", "npmjs.com", "npm.pkg.github.com"), NpmUrlParser::parseRegistryPath),
            new EcosystemRouter(List.of("pypi.org", "pythonhosted.org", "pypi.python.org"), PypiUrlParser::parseRegistryPath),
            new EcosystemRouter(List.of("maven.org", "maven.apache.org"), MavenUrlParser::parseCentralPath)
    );

    @Timed(value = "silicaproxy.service.urlparser.parseurl",
            description = "Duration of extracting package metadata from the URL",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public ParsedPackage parseUrl(String urlString) {
        try {
            URI uri = URI.create(urlString);
            String host = uri.getHost();
            String path = uri.getPath();

            if (host == null || path == null) {
                return ParsedPackage.unknown(ParsedPackage.UNKNOWN);
            }

            for (EcosystemRouter router : ROUTERS) {
                if (router.matches(host)) {
                    return router.parser().apply(path);
                }
            }
            return detectFromPath(host, path);
        } catch (Exception ignored) {
            // fallback
        }

        return ParsedPackage.unknown(ParsedPackage.UNKNOWN);
    }

    /**
     * Layer 3, called by {@link PackageIdentificationService} only when {@link #parseUrl(String)} could not name an
     * ecosystem : recognises npm metadata traffic on hosts the proxy does not know (private
     * registries, npm.jsr.io…) from the client headers or from an unambiguous registry path
     * shape. The version is always "unknown" (nothing to vet), so the request is still bypassed ;
     * the package name is best-effort, for debug logs only.
     */
    @Timed(value = "silicaproxy.service.urlparser.detectnpmmetadata",
            description = "Duration of the header/path based npm metadata detection",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<ParsedPackage> detectNpmMetadata(String urlString, HttpHeaders headers) {
        return pathOf(urlString).flatMap(path -> NpmUrlParser.detectMetadata(path, headers));
    }

    /**
     * Layer 2 for PyPI and Maven, called by {@link PackageIdentificationService} only when neither
     * {@link #parseUrl(String)} nor {@link #detectNpmMetadata} named an ecosystem : recognises a
     * PyPI or Maven client from its headers. A PyPI client's sdist ({@code .tar.gz}) is identified
     * with its version, whatever the layout, the header standing in for the known-prefix context ;
     * any other request is only tagged with the ecosystem (version "unknown", still bypassed). The
     * headers can only add an identification the URL did not give, never remove one.
     */
    @Timed(value = "silicaproxy.service.urlparser.detectclientecosystem",
            description = "Duration of the header based PyPI/Maven client detection",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<ParsedPackage> detectClientEcosystem(String urlString, HttpHeaders headers) {
        if (PypiUrlParser.isClient(headers)) {
            return Optional.of(pathOf(urlString).map(PypiUrlParser::parseClientPath)
                    .orElseGet(() -> ParsedPackage.unknown("pypi")));
        }
        if (MavenUrlParser.isClient(headers)) {
            return Optional.of(MavenUrlParser.clientTraffic());
        }
        return Optional.empty();
    }

    /**
     * Identifies an npm tarball from its (decoded) URL path, whatever the host : npmjs layout,
     * optionally behind a repository prefix, npm.jsr.io and GitHub Packages layouts.
     */
    public static Optional<ParsedPackage> parseNpmTarball(String path) {
        return NpmUrlParser.parseTarball(path);
    }

    /**
     * Whether {@code url}'s path has the {@code .tgz} extension every npm tarball layout but GitHub
     * Packages uses ; false for an unparseable URL.
     */
    public static boolean hasNpmTarballExtension(String url) {
        return pathOf(url).map(path -> path.endsWith(NpmUrlParser.TARBALL_EXTENSION)).orElse(false);
    }

    private static ParsedPackage detectFromPath(String host, String path) {
        Optional<ParsedPackage> npmTarball = NpmUrlParser.parseTarball(path);
        if (npmTarball.isPresent()) {
            return npmTarball.get();
        }
        Optional<ParsedPackage> pypi = PypiUrlParser.parsePath(path);
        if (pypi.isPresent()) {
            return pypi.get();
        }
        return MavenUrlParser.parseRepositoryPath(host, path)
                .orElseGet(() -> ParsedPackage.unknown(ParsedPackage.UNKNOWN));
    }

    // Decoded path of the URL ; empty when the URL is unparseable or has no path.
    private static Optional<String> pathOf(String url) {
        try {
            return Optional.ofNullable(URI.create(url).getPath());
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
