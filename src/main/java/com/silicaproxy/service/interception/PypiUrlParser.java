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
 * PyPI part of {@link UrlParserService}. Patterns apply to the file name alone (last path
 * segment). A wheel name is fully self-describing (PEP 427), so a wheel is identified whatever the
 * path ; an sdist name ("foo-1.0.tar.gz") is not, so an sdist is only read behind a known PyPI
 * prefix ({@link #LAYOUTS}) or from a PyPI client ({@link #isClient}).
 */
@NullMarked
final class PypiUrlParser {

    private static final String ECOSYSTEM = ParsedPackage.PYPI;

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
    private static final Pattern WHEEL_FILENAME =
            Pattern.compile("^([^/]+?)-(\\d[^-/]*)(?:-\\d[^-/]*)?-(?:py|cp|pp|jy|ip)[^/]*\\.whl$");
    // Filename-anchored, not directory-anchored: real PyPI sdist storage is content-addressed
    // (hash directories), so a package-name-as-directory backreference only matches the legacy
    // /packages/source/{letter}/{name}/ layout that pip no longer requests in practice.
    private static final Pattern SDIST_FILENAME = Pattern.compile("^([^/]+)-([\\d\\.]+[^/]*)\\.tar\\.gz$");
    // Prefixes under which a ".tar.gz" is a PyPI sdist.
    private static final List<Pattern> LAYOUTS = List.of(
            // pypi.org, files.pythonhosted.org and mirrors of that layout
            Pattern.compile("^/packages/"),
            // Nexus 3 : "/repository/{repo}/packages/", optionally under the "/nexus" context path
            Pattern.compile("^/(?:nexus/)?repository/[^/]+/packages/"),
            // Artifactory : "/artifactory/api/pypi/{repo}/packages/"
            Pattern.compile("^/artifactory/api/pypi/[^/]+/packages/"),
            // devpi : "/{user}/{index}/+f/"
            Pattern.compile("^/[^/]+/[^/]+/\\+f/"),
            // GitLab : "/api/v4/projects/{id}/packages/pypi/files/", optionally under a relative URL root
            Pattern.compile("^(?:/[^/]+)?/api/v4/projects/[^/]+/packages/pypi/files/")
    );

    // pip and uv follow their version with a JSON blob ("pip/24.0 {...}") : the leading token is
    // enough. PEP 691 JSON simple-index media type, requested by pip and uv.
    private static final List<String> USER_AGENT_PREFIXES = List.of("pip/", "uv/", "poetry/", "pdm/");
    private static final String SIMPLE_JSON_MEDIA_TYPE = "application/vnd.pypi.simple.v1+json";

    private PypiUrlParser() {
    }

    /** Known PyPI host : a wheel or sdist, or a PyPI resource naming no version. */
    static ParsedPackage parseRegistryPath(String path) {
        return parsePath(path).orElseGet(() -> ParsedPackage.unknown(ECOSYSTEM));
    }

    /** Wheel whatever the path, then sdist behind a known PyPI prefix, whatever the host. */
    static Optional<ParsedPackage> parsePath(String path) {
        String file = lastSegment(path);
        Optional<ParsedPackage> wheel = matchFile(WHEEL_FILENAME, file);
        if (wheel.isPresent()) {
            return wheel;
        }
        for (Pattern prefix : LAYOUTS) {
            if (prefix.matcher(path).lookingAt()) {
                return matchFile(SDIST_FILENAME, file);
            }
        }
        return Optional.empty();
    }

    /** From a PyPI client : an sdist whatever the layout, the client standing in for the prefix. */
    static ParsedPackage parseClientPath(String path) {
        return matchFile(SDIST_FILENAME, lastSegment(path)).orElseGet(() -> ParsedPackage.unknown(ECOSYSTEM));
    }

    static boolean isClient(HttpHeaders headers) {
        return ClientHeaders.acceptContains(headers, SIMPLE_JSON_MEDIA_TYPE)
                || ClientHeaders.userAgentStartsWith(headers, USER_AGENT_PREFIXES);
    }

    // Groups : (1) name, (2) version.
    private static Optional<ParsedPackage> matchFile(Pattern filePattern, String file) {
        Matcher m = filePattern.matcher(file);
        return m.matches() ? Optional.of(new ParsedPackage(m.group(1), m.group(2), ECOSYSTEM)) : Optional.empty();
    }

    private static String lastSegment(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
