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
import org.springframework.stereotype.Service;
import io.micrometer.core.annotation.Timed;

import java.net.URI;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts package/version/ecosystem from the absolute URL intercepted by the proxy (npm,
 * PyPI, Maven paths). Called by {@code ProxyController} first on each request, before
 * any security decision ; returns "unknown" if the URL does not match any known pattern, which
 * then bypasses the security check (resource not identifiable as a package).
 *
 * <p>Two detection layers : (1) known host → direct parser ; (2) structural fallback by
 * path pattern for private registries (Verdaccio, devpi, artifact repositories, repo.spring.io…).
 */
@Service
@NullMarked
public class UrlParserService {

    private static final Pattern NPM_UNSCOPED_TARBALL_PATTERN = Pattern.compile("^/([^/]+)/-/\\1-([\\d\\.]+.*)\\.tgz$");
    private static final Pattern NPM_SCOPED_TARBALL_PATTERN = Pattern.compile("^/(@[^/]+)/([^/]+)/-/\\2-([\\d\\.]+.*)\\.tgz$");
    private static final Pattern NPM_METADATA_PATTERN = Pattern.compile("^/([^/]+|@[^/]+/[^/]+)$");

    private static final Pattern PYPI_JSON_PATTERN = Pattern.compile("^/pypi/([^/]+)/json$");
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

    private static final Pattern MAVEN_PATTERN = Pattern.compile("^/maven2/(.+)/([^/]+)/([^/]+)/[^/]+$");
    private static final Pattern MAVEN_STRUCTURAL_PATTERN =
            Pattern.compile("^/[^/]+/(.+)/([^/]+)/([^/]+)/[^/]+\\.(?:jar|pom|aar|war|ear|zip|module)$");

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

    private static ParsedPackage detectFromPath(String path) {
        Matcher unscopedNpm = NPM_UNSCOPED_TARBALL_PATTERN.matcher(path);
        if (unscopedNpm.matches()) {
            return new ParsedPackage(unscopedNpm.group(1), unscopedNpm.group(2), "npm");
        }
        Matcher scopedNpm = NPM_SCOPED_TARBALL_PATTERN.matcher(path);
        if (scopedNpm.matches()) {
            return new ParsedPackage(scopedNpm.group(1) + "/" + scopedNpm.group(2), scopedNpm.group(3), "npm");
        }
        Matcher m = PYPI_JSON_PATTERN.matcher(path);
        if (m.matches()) {
            return new ParsedPackage(m.group(1), "latest", "pypi");
        }
        m = PYPI_WHL_PATTERN.matcher(path);
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

    private static ParsedPackage parseNpmUrl(String path) {
        Matcher unscopedMatcher = NPM_UNSCOPED_TARBALL_PATTERN.matcher(path);
        if (unscopedMatcher.matches()) {
            return new ParsedPackage(unscopedMatcher.group(1), unscopedMatcher.group(2), "npm");
        }
        Matcher scopedMatcher = NPM_SCOPED_TARBALL_PATTERN.matcher(path);
        if (scopedMatcher.matches()) {
            return new ParsedPackage(
                    scopedMatcher.group(1) + "/" + scopedMatcher.group(2),
                    scopedMatcher.group(3),
                    "npm");
        }
        Matcher metaMatcher = NPM_METADATA_PATTERN.matcher(path);
        if (metaMatcher.matches()) {
            return new ParsedPackage(metaMatcher.group(1), "latest", "npm");
        }
        return new ParsedPackage("unknown", "unknown", "npm");
    }

    private static ParsedPackage parsePypiUrl(String path) {
        Matcher m = PYPI_JSON_PATTERN.matcher(path);
        if (m.matches()) {
            return new ParsedPackage(m.group(1), "latest", "pypi");
        }
        m = PYPI_WHL_PATTERN.matcher(path);
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
