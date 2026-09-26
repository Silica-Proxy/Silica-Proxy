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

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * npm part of {@link UrlParserService} : tarball layouts (whatever the host) and the header/path
 * based metadata detection.
 */
@NullMarked
final class NpmUrlParser {

    private static final String ECOSYSTEM = "npm";

    // npmjs layout "/{name}/-/{name}-{version}.tgz" (optionally scoped) is parsed by string
    // splitting in parseNpmjsLayoutTarball rather than by a regex : accepting any repository
    // prefix in front of it with a regex needs overlapping quantifiers, a ReDoS risk on
    // client-supplied URLs.
    private static final String TARBALL_SEPARATOR = "/-/";
    static final String TARBALL_EXTENSION = ".tgz";
    // npm.jsr.io : "/~/{rev}/@jsr/{scope}__{name}/{version}.tgz".
    private static final Pattern JSR_TARBALL_PATTERN = Pattern.compile("^/~/\\d+/(@jsr/[^/]+)/(\\d[^/]*)\\.tgz$");
    // npm.pkg.github.com : "/download/@{owner}/{name}/{version}/{sha}".
    private static final Pattern GITHUB_TARBALL_PATTERN =
            Pattern.compile("^/download/(@[^/]+/[^/]+)/(\\d[^/]*)/[0-9a-f]+$");

    // Layer 3 (npm metadata) path shapes that cannot reasonably be anything but an npm registry.
    // A bare "/{name}" is deliberately NOT here : it is too ambiguous without a client header.
    // URI.getPath() has already decoded "%2f" to "/" so scoped names arrive as "/@scope/name".
    private static final Pattern SCOPED_PACKUMENT_PATTERN =
            Pattern.compile("^/(@[^/@]+/[^/@]+)(?:/[^/]+)?$");
    private static final Pattern UNSCOPED_PACKUMENT_PATTERN = Pattern.compile("^/([^/@-][^/]*)(?:/[^/]+)?$");
    private static final Pattern REGISTRY_API_PATTERN =
            Pattern.compile("^/-/(?:v1/|npm/|package/|user/|ping|whoami).*$");
    private static final Pattern DASH_SEGMENT_PATTERN = Pattern.compile("^/(?:@[^/]+/)?[^/@-][^/]*/-/.*$");

    // Abbreviated packument media type requested by npm, pnpm, yarn (berry) and bun.
    private static final String INSTALL_MEDIA_TYPE = "application/vnd.npm.install-v1+json";
    // pnpm and yarn classic also embed "npm/?" in their User-Agent, but the leading token is enough.
    private static final List<String> USER_AGENT_PREFIXES = List.of("npm/", "pnpm/", "yarn/", "bun/");
    // npm CLI request headers (npm-command, npm-scope, npm-in-ci, npm-session, npm-auth-type) and
    // its fetcher's (pacote-version, pacote-req-type, pacote-pkg-id).
    private static final List<String> HEADER_PREFIXES = List.of("npm-", "pacote-");

    private NpmUrlParser() {
    }

    /** Known npm registry host : a tarball, or an npm resource naming no version. */
    static ParsedPackage parseRegistryPath(String path) {
        return parseTarball(path).orElseGet(() -> ParsedPackage.unknown(ECOSYSTEM));
    }

    /** See {@link UrlParserService#parseNpmTarball(String)}. */
    static Optional<ParsedPackage> parseTarball(String path) {
        Optional<ParsedPackage> npmjsLayout = parseNpmjsLayoutTarball(path);
        if (npmjsLayout.isPresent()) {
            return npmjsLayout;
        }
        for (Pattern pattern : List.of(JSR_TARBALL_PATTERN, GITHUB_TARBALL_PATTERN)) {
            Matcher m = pattern.matcher(path);
            if (m.matches()) {
                return Optional.of(new ParsedPackage(m.group(1), m.group(2), ECOSYSTEM));
            }
        }
        return Optional.empty();
    }

    /** See {@link UrlParserService#detectNpmMetadata(String, HttpHeaders)}. */
    static Optional<ParsedPackage> detectMetadata(String path, HttpHeaders headers) {
        if (!(isClient(headers) || isUnambiguousPath(path))) {
            return Optional.empty();
        }
        Matcher scoped = SCOPED_PACKUMENT_PATTERN.matcher(path);
        if (scoped.matches()) {
            return Optional.of(new ParsedPackage(scoped.group(1), ParsedPackage.UNKNOWN, ECOSYSTEM));
        }
        Matcher unscoped = UNSCOPED_PACKUMENT_PATTERN.matcher(path);
        if (unscoped.matches()) {
            return Optional.of(new ParsedPackage(unscoped.group(1), ParsedPackage.UNKNOWN, ECOSYSTEM));
        }
        return Optional.of(ParsedPackage.unknown(ECOSYSTEM));
    }

    // "{prefix}/{name}/-/{name}-{version}.tgz" or "{prefix}/@{scope}/{name}/-/{name}-{version}.tgz",
    // where {prefix} is empty (npmjs) or a repository path (Artifactory
    // "/artifactory/api/npm/{repo}", Nexus "/repository/{repo}", CodeArtifact "/npm/{repo}").
    // Artifactory writes the scoped file as "-/@{scope}/{name}-{version}.tgz". The version must
    // start with a digit or a dot, like the historical regex "[\d\.]+.*".
    private static Optional<ParsedPackage> parseNpmjsLayoutTarball(String path) {
        int separator = path.lastIndexOf(TARBALL_SEPARATOR);
        if (separator <= 0 || !path.endsWith(TARBALL_EXTENSION)) {
            return Optional.empty();
        }
        String head = path.substring(0, separator);
        String file = path.substring(separator + TARBALL_SEPARATOR.length(), path.length() - TARBALL_EXTENSION.length());
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
        return Optional.of(new ParsedPackage(fullName, versionAndRest, ECOSYSTEM));
    }

    private static boolean isVersionStart(char c) {
        return c == '.' || c >= '0' && c <= '9';
    }

    private static boolean isClient(HttpHeaders headers) {
        return ClientHeaders.acceptContains(headers, INSTALL_MEDIA_TYPE)
                || ClientHeaders.userAgentStartsWith(headers, USER_AGENT_PREFIXES)
                || ClientHeaders.hasHeaderNameStartingWith(headers, HEADER_PREFIXES);
    }

    private static boolean isUnambiguousPath(String path) {
        return SCOPED_PACKUMENT_PATTERN.matcher(path).matches()
                || REGISTRY_API_PATTERN.matcher(path).matches()
                || DASH_SEGMENT_PATTERN.matcher(path).matches();
    }
}
