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
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import io.micrometer.core.annotation.Timed;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts package/version/ecosystem from the absolute URL intercepted by the proxy (npm,
 * PyPI, Maven paths). Called by {@code ProxyController} first on each request, before
 * any security decision ; returns "unknown" if the URL does not match any known pattern, which
 * then bypasses the security check (resource not identifiable as a package).
 *
 * <p>Three detection layers : (1) known host → direct parser ; (2) structural fallback by
 * path pattern for private registries (Verdaccio, devpi, artifact repositories, repo.spring.io…) ;
 * (3) {@link #detectNpmMetadata}, an npm-only ecosystem hint from the client headers (Accept /
 * User-Agent / npm-* headers) or from an unambiguous npm registry path shape. Layer 3 never
 * yields a version : it only tags metadata traffic (packuments, dist-tags, search) with the
 * right ecosystem so bypass logs and metrics stop reporting it as "unknown".
 */
@Service
@NullMarked
public class UrlParserService {

    // npmjs layout "/{name}/-/{name}-{version}.tgz" (optionally scoped) is parsed by string
    // splitting in parseNpmjsLayoutTarball rather than by a regex : accepting any repository
    // prefix in front of it with a regex needs overlapping quantifiers, a ReDoS risk on
    // client-supplied URLs.
    private static final String NPM_TARBALL_SEPARATOR = "/-/";
    private static final String NPM_TARBALL_EXTENSION = ".tgz";
    // npm.jsr.io : "/~/{rev}/@jsr/{scope}__{name}/{version}.tgz".
    private static final Pattern NPM_JSR_TARBALL_PATTERN = Pattern.compile("^/~/\\d+/(@jsr/[^/]+)/(\\d[^/]*)\\.tgz$");
    // npm.pkg.github.com : "/download/@{owner}/{name}/{version}/{sha}".
    private static final Pattern NPM_GITHUB_TARBALL_PATTERN =
            Pattern.compile("^/download/(@[^/]+/[^/]+)/(\\d[^/]*)/[0-9a-f]+$");

    // Version group is [^-/]* (not .*): compiled-wheel filenames repeat the ABI tag
    // (e.g. "tensorflow-1.6.0-cp27-cp27m-macosx_10_11_x86_64.whl"), and a greedy ".*" backtracks
    // to the LAST "-cp"/"-py" occurrence instead of the first, swallowing part of the tag into
    // the version ("1.6.0-cp27"). Forbidding '-' after the leading digit stops the version at
    // the first tag boundary, matching how PyPI itself delimits {name}-{version}-{tag}.whl.
    // The name group is lazy ([^/]+?, not [^/]+): a greedy name backtracks past the FIRST
    // "-digit" boundary when the optional build tag segment is present (e.g.
    // "sentry-22.3.0-0-py38-none-any.whl" is {name}-{version}-{build tag}-{python tag}...),
    // swallowing the real version into the name and leaving only the build tag digit as the
    // captured "version". The optional (?:-\d[^-/]*)? group consumes that build tag explicitly.
    // Implementation tag alternatives per PEP 425: py (generic), cp (CPython), pp (PyPy),
    // jy (Jython), ip (IronPython) -- these are the only 5 abbreviations the spec defines.
    private static final Pattern PYPI_WHL_PATTERN =
            Pattern.compile("^/packages/.*?/([^/]+?)-(\\d[^-/]*)(?:-\\d[^-/]*)?-(?:py|cp|pp|jy|ip)[^/]*\\.whl$");
    // Filename-anchored, not directory-anchored: real PyPI sdist storage is content-addressed
    // (hash directories), so a package-name-as-directory backreference only matches the legacy
    // /packages/source/{letter}/{name}/ layout that pip no longer requests in practice. The
    // version group is restricted to [^/]* (not .*) so it can't "tunnel" through a "/" and
    // wrongly consume a directory segment when the legacy layout repeats the name in the path.
    private static final Pattern PYPI_TAR_PATTERN = Pattern.compile("^/packages/.*?/([^/]+)-([\\d\\.]+[^/]*)\\.tar\\.gz$");

    // Excludes maven-metadata.xml and checksum files (.sha1/.sha256/.sha512/.md5/.asc): those
    // have no version segment, and without this exclusion the pattern misreads the artifactId
    // as the version.
    private static final Pattern MAVEN_PATTERN = Pattern.compile(
            "^/maven2/(.+)/([^/]+)/([^/]+)/(?!maven-metadata\\.xml$)"
                    + "(?!.+\\.(?:sha1|sha256|sha512|md5|asc)$)[^/]+$");
    private static final Pattern MAVEN_STRUCTURAL_PATTERN =
            Pattern.compile("^/[^/]+/(.+)/([^/]+)/([^/]+)/[^/]+\\.(?:jar|pom|aar|war|ear|zip|module)$");

    // Layer 3 (npm metadata) path shapes that cannot reasonably be anything but an npm registry.
    // A bare "/{name}" is deliberately NOT here : it is too ambiguous without a client header.
    // URI.getPath() has already decoded "%2f" to "/" so scoped names arrive as "/@scope/name".
    private static final Pattern NPM_SCOPED_PACKUMENT_PATTERN =
            Pattern.compile("^/(@[^/@]+/[^/@]+)(?:/[^/]+)?$");
    private static final Pattern NPM_UNSCOPED_PACKUMENT_PATTERN = Pattern.compile("^/([^/@-][^/]*)(?:/[^/]+)?$");
    private static final Pattern NPM_REGISTRY_API_PATTERN =
            Pattern.compile("^/-/(?:v1/|npm/|package/|user/|ping|whoami).*$");
    private static final Pattern NPM_DASH_SEGMENT_PATTERN = Pattern.compile("^/(?:@[^/]+/)?[^/@-][^/]*/-/.*$");

    // Abbreviated packument media type requested by npm, pnpm, yarn (berry) and bun.
    private static final String NPM_INSTALL_MEDIA_TYPE = "application/vnd.npm.install-v1+json";
    // pnpm and yarn classic also embed "npm/?" in their User-Agent, but the leading token is enough.
    private static final List<String> NPM_USER_AGENT_PREFIXES = List.of("npm/", "pnpm/", "yarn/", "bun/");
    // npm CLI request headers (npm-command, npm-scope, npm-in-ci, npm-session, npm-auth-type) and
    // its fetcher's (pacote-version, pacote-req-type, pacote-pkg-id).
    private static final List<String> NPM_HEADER_PREFIXES = List.of("npm-", "pacote-");

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
            new EcosystemRouter(List.of("npmjs.org", "npmjs.com", "npm.pkg.github.com"), UrlParserService::parseNpmUrl),
            new EcosystemRouter(List.of("pypi.org", "pythonhosted.org", "pypi.python.org"), UrlParserService::parsePypiUrl),
            new EcosystemRouter(List.of("maven.org", "maven.apache.org"), UrlParserService::parseMavenUrl)
    );

    public record ParsedPackage(String packageName, String version, String ecosystem) {}

    @Timed(value = "silicaproxy.service.urlparser.parseurl",
            description = "Duration of extracting package metadata from the URL",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public ParsedPackage parseUrl(String urlString) {
        try {
            URI uri = URI.create(urlString);
            String host = uri.getHost();
            String path = uri.getPath();

            if (host == null || path == null) {
                return new ParsedPackage("unknown", "unknown", "unknown");
            }

            for (EcosystemRouter router : ROUTERS) {
                if (router.matches(host)) {
                    return router.parser().apply(path);
                }
            }
            return detectFromPath(path);
        } catch (Exception ignored) {
            // fallback
        }

        return new ParsedPackage("unknown", "unknown", "unknown");
    }

    /**
     * Layer 3, called by the controller only when {@link #parseUrl(String)} could not name an
     * ecosystem : recognises npm metadata traffic on hosts the proxy does not know (private
     * registries, npm.jsr.io…) from the client headers or from an unambiguous registry path
     * shape. The version is always "unknown" (nothing to vet), so the request is still bypassed ;
     * the package name is best-effort, for debug logs only.
     */
    @Timed(value = "silicaproxy.service.urlparser.detectnpmmetadata",
            description = "Duration of the header/path based npm metadata detection",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<ParsedPackage> detectNpmMetadata(String urlString, HttpHeaders headers) {
        try {
            String path = URI.create(urlString).getPath();
            if (path == null || !(isNpmClient(headers) || isUnambiguousNpmPath(path))) {
                return Optional.empty();
            }
            Matcher scoped = NPM_SCOPED_PACKUMENT_PATTERN.matcher(path);
            if (scoped.matches()) {
                return Optional.of(new ParsedPackage(scoped.group(1), "unknown", "npm"));
            }
            Matcher unscoped = NPM_UNSCOPED_PACKUMENT_PATTERN.matcher(path);
            if (unscoped.matches()) {
                return Optional.of(new ParsedPackage(unscoped.group(1), "unknown", "npm"));
            }
            return Optional.of(new ParsedPackage("unknown", "unknown", "npm"));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    /**
     * Identifies an npm tarball from its (decoded) URL path, whatever the host : npmjs layout,
     * optionally behind a repository prefix, npm.jsr.io and GitHub Packages layouts.
     */
    public static Optional<ParsedPackage> parseNpmTarball(String path) {
        Optional<ParsedPackage> npmjsLayout = parseNpmjsLayoutTarball(path);
        if (npmjsLayout.isPresent()) {
            return npmjsLayout;
        }
        for (Pattern pattern : List.of(NPM_JSR_TARBALL_PATTERN, NPM_GITHUB_TARBALL_PATTERN)) {
            Matcher m = pattern.matcher(path);
            if (m.matches()) {
                return Optional.of(new ParsedPackage(m.group(1), m.group(2), "npm"));
            }
        }
        return Optional.empty();
    }

    // "{prefix}/{name}/-/{name}-{version}.tgz" or "{prefix}/@{scope}/{name}/-/{name}-{version}.tgz",
    // where {prefix} is empty (npmjs) or a repository path (Artifactory
    // "/artifactory/api/npm/{repo}", Nexus "/repository/{repo}", CodeArtifact "/npm/{repo}").
    // Artifactory writes the scoped file as "-/@{scope}/{name}-{version}.tgz". The version must
    // start with a digit or a dot, like the historical regex "[\d\.]+.*".
    private static Optional<ParsedPackage> parseNpmjsLayoutTarball(String path) {
        int separator = path.lastIndexOf(NPM_TARBALL_SEPARATOR);
        if (separator <= 0 || !path.endsWith(NPM_TARBALL_EXTENSION)) {
            return Optional.empty();
        }
        String head = path.substring(0, separator);
        String file = path.substring(separator + NPM_TARBALL_SEPARATOR.length(), path.length() - NPM_TARBALL_EXTENSION.length());
        int lastSlash = head.lastIndexOf('/');
        String name = head.substring(lastSlash + 1);
        if (name.isEmpty() || name.charAt(0) == '@') {
            return Optional.empty();
        }
        int scopeSlash = lastSlash > 0 ? head.lastIndexOf('/', lastSlash - 1) : -1;
        String parentSegment = lastSlash > 0 ? head.substring(scopeSlash + 1, lastSlash) : "";
        boolean scoped = parentSegment.length() > 1 && parentSegment.charAt(0) == '@';
        String fullName = scoped ? parentSegment + "/" + name : name;

        String versionAndRest;
        if (file.startsWith(name + "-")) {
            versionAndRest = file.substring(name.length() + 1);
        } else if (scoped && file.startsWith(fullName + "-")) {
            versionAndRest = file.substring(fullName.length() + 1);
        } else {
            return Optional.empty();
        }
        if (versionAndRest.isEmpty() || !isVersionStart(versionAndRest.charAt(0))) {
            return Optional.empty();
        }
        return Optional.of(new ParsedPackage(fullName, versionAndRest, "npm"));
    }

    private static boolean isVersionStart(char c) {
        return c == '.' || c >= '0' && c <= '9';
    }

    private static ParsedPackage detectFromPath(String path) {
        Optional<ParsedPackage> npmTarball = parseNpmTarball(path);
        if (npmTarball.isPresent()) {
            return npmTarball.get();
        }
        Matcher m = PYPI_WHL_PATTERN.matcher(path);
        if (m.matches()) {
            return new ParsedPackage(m.group(1), m.group(2), "pypi");
        }
        m = PYPI_TAR_PATTERN.matcher(path);
        if (m.matches()) {
            return new ParsedPackage(m.group(1), m.group(2), "pypi");
        }
        m = MAVEN_STRUCTURAL_PATTERN.matcher(path);
        if (m.matches()) {
            String groupId = m.group(1).replace('/', '.');
            return new ParsedPackage(groupId + ":" + m.group(2), m.group(3), "maven");
        }
        return new ParsedPackage("unknown", "unknown", "unknown");
    }

    private static boolean isNpmClient(HttpHeaders headers) {
        if (containsNpmInstallMediaType(headers.getFirst(HttpHeaders.ACCEPT))
                || hasNpmUserAgent(headers.getFirst(HttpHeaders.USER_AGENT))) {
            return true;
        }
        for (String name : headers.headerNames()) {
            String lower = name.toLowerCase(Locale.ROOT);
            for (String prefix : NPM_HEADER_PREFIXES) {
                if (lower.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean containsNpmInstallMediaType(@Nullable String accept) {
        return accept != null && accept.toLowerCase(Locale.ROOT).contains(NPM_INSTALL_MEDIA_TYPE);
    }

    private static boolean hasNpmUserAgent(@Nullable String userAgent) {
        if (userAgent == null) {
            return false;
        }
        String lower = userAgent.toLowerCase(Locale.ROOT);
        for (String prefix : NPM_USER_AGENT_PREFIXES) {
            if (lower.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUnambiguousNpmPath(String path) {
        return NPM_SCOPED_PACKUMENT_PATTERN.matcher(path).matches()
                || NPM_REGISTRY_API_PATTERN.matcher(path).matches()
                || NPM_DASH_SEGMENT_PATTERN.matcher(path).matches();
    }

    private static ParsedPackage parseNpmUrl(String path) {
        return parseNpmTarball(path).orElseGet(() -> new ParsedPackage("unknown", "unknown", "npm"));
    }

    private static ParsedPackage parsePypiUrl(String path) {
        Matcher m = PYPI_WHL_PATTERN.matcher(path);
        if (m.matches()) {
            return new ParsedPackage(m.group(1), m.group(2), "pypi");
        }
        m = PYPI_TAR_PATTERN.matcher(path);
        if (m.matches()) {
            return new ParsedPackage(m.group(1), m.group(2), "pypi");
        }
        return new ParsedPackage("unknown", "unknown", "pypi");
    }

    private static ParsedPackage parseMavenUrl(String path) {
        Matcher m = MAVEN_PATTERN.matcher(path);
        if (m.matches()) {
            String groupId = m.group(1).replace('/', '.');
            return new ParsedPackage(groupId + ":" + m.group(2), m.group(3), "maven");
        }
        return new ParsedPackage("unknown", "unknown", "maven");
    }
}
