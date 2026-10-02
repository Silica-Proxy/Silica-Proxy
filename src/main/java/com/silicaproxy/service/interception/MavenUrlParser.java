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

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maven part of {@link UrlParserService} : the Maven Central layout, the repository layouts of
 * any other host, and the client detection.
 */
@NullMarked
final class MavenUrlParser {

    private static final String ECOSYSTEM = ParsedPackage.MAVEN;

    // Excludes maven-metadata.xml and checksum files (.sha1/.sha256/.sha512/.md5/.asc): those
    // have no version segment, and without this exclusion the pattern misreads the artifactId
    // as the version.
    private static final Pattern CENTRAL_PATTERN = Pattern.compile(
            "^/maven2/(.+)/([^/]+)/([^/]+)/(?!maven-metadata\\.xml$)"
                    + "(?!.+\\.(?:sha1|sha256|sha512|md5|asc)$)[^/]+$");

    private static final Pattern GRADLE_PORTAL_PATTERN =
            Pattern.compile("^/([^/]+)/([^/]+)/([^/]+)/[0-9a-f]{64}/([^/]+)$");

    private record RepositoryLayout(@Nullable String hostSuffix, Pattern prefix) {
        boolean matchesHost(String host) {
            return hostSuffix == null || Hosts.isDomainOrSubdomain(host, hostSuffix);
        }
    }

    // Structural fallback (any host) : the repository prefix is stripped, then the rest is read
    // as "{groupId path}/{artifactId}/{version}/{file}" by parseCoordinates. Nothing in a path
    // tells where the prefix ends and the groupId begins, so the prefixes of the known repository
    // managers are listed explicitly ; the last entry keeps the historical reading of exactly one
    // prefix segment (repo.spring.io "/release", plugins.gradle.org "/m2"…). The ambiguous shapes
    // ("/maven/{repo}", "/{owner}/{repo}", no prefix) only apply on their own host, so that a
    // generic repository named "maven" is not cut one segment too far. First match wins, with no
    // fallthrough : a later, shorter prefix would fold the repository name into the groupId.
    private static final List<RepositoryLayout> LAYOUTS = List.of(
            // AWS CodeArtifact : "{domain}-{owner}.d.codeartifact.{region}.amazonaws.com/maven/{repo}/"
            new RepositoryLayout("amazonaws.com", Pattern.compile("^/maven/[^/]+/")),
            // Azure Artifacts : "/{org}/{project}/_packaging/{feed}/maven/v1/", project optional
            new RepositoryLayout("pkgs.dev.azure.com",
                    Pattern.compile("^/[^/]+/(?:[^/]+/)?_packaging/[^/]+/maven/v1/")),
            // GitHub Packages : "/{owner}/{repo}/"
            new RepositoryLayout("maven.pkg.github.com", Pattern.compile("^/[^/]+/[^/]+/")),
            // Google Maven : "dl.google.com/dl/android/maven2/", and maven.google.com (which
            // redirects there) with no prefix
            new RepositoryLayout("dl.google.com", Pattern.compile("^/dl/android/maven2/")),
            new RepositoryLayout("maven.google.com", Pattern.compile("^/")),
            // JitPack : no prefix
            new RepositoryLayout("jitpack.io", Pattern.compile("^/")),
            // Nexus 3 : "/repository/{repo}/", optionally under the "/nexus" context path
            new RepositoryLayout(null, Pattern.compile("^/(?:nexus/)?repository/[^/]+/")),
            // Nexus 2 : "/content/repositories/{repo}/" and "/content/groups/{repo}/", optionally
            // under the "/nexus" context path (oss.sonatype.org serves them at the root)
            new RepositoryLayout(null, Pattern.compile("^/(?:nexus/)?content/(?:repositories|groups)/[^/]+/")),
            // Artifactory : "/artifactory/{repo}/"
            new RepositoryLayout(null, Pattern.compile("^/artifactory/[^/]+/")),
            // GitLab : "/api/v4/projects/{id}/packages/maven/" or "/api/v4/groups/{id}/-/packages/maven/",
            // optionally under a relative URL root
            new RepositoryLayout(null,
                    Pattern.compile("^(?:/[^/]+)?/api/v4/(?:projects/[^/]+|groups/[^/]+/-)/packages/maven/")),
            // Any other repository : one prefix segment
            new RepositoryLayout(null, Pattern.compile("^/[^/]+/"))
    );
    // Checksums, signatures and maven-metadata.xml name no version : not artifacts.
    private static final List<String> ARTIFACT_EXTENSIONS =
            List.of(".jar", ".pom", ".aar", ".war", ".ear", ".zip", ".module");
    private static final String SNAPSHOT_QUALIFIER = "SNAPSHOT";

    // Maven and Gradle follow their version with platform details : the leading token is enough.
    private static final List<String> USER_AGENT_PREFIXES =
            List.of("apache-maven/", "gradle/", "apache ivy/", "coursier/");

    private MavenUrlParser() {
    }

    /** Known Maven Central host : "/maven2/{group}/{artifact}/{version}/{file}". */
    static ParsedPackage parseCentralPath(String path) {
        Matcher m = CENTRAL_PATTERN.matcher(path);
        if (!m.matches()) {
            return ParsedPackage.unknown(ECOSYSTEM);
        }
        // Groups : (1) groupId path, (2) artifactId, (3) version.
        return new ParsedPackage(m.group(1).replace('/', '.') + ":" + m.group(2), m.group(3), ECOSYSTEM);
    }

    /** Any other host : the first layout matching the host and the path decides, see {@link #LAYOUTS}. */
    static Optional<ParsedPackage> parseRepositoryPath(String host, String path) {
        return parseWithLayouts(host, path).or(() -> parseGradlePortalPath(path));
    }

    private static Optional<ParsedPackage> parseWithLayouts(String host, String path) {
        for (RepositoryLayout layout : LAYOUTS) {
            if (layout.matchesHost(host)) {
                Matcher prefix = layout.prefix().matcher(path);
                if (prefix.lookingAt()) {
                    return parseCoordinates(path.substring(prefix.end()));
                }
            }
        }
        return Optional.empty();
    }

    // Content-addressed layout of the Gradle plugin portal downloads (plugins.gradle.org redirects
    // the .jar/.module files to plugins-artifacts.gradle.org) :
    // "/{groupId}/{artifactId}/{version}/{sha256}/{file}". The groupId keeps its dots (one
    // segment) and a 64-hex directory sits between the version and the file, so the generic
    // layouts read the hash as the version and reject the file. Matched by shape, on any host,
    // and only once every repository layout has failed : a URL the layouts already identify never
    // reaches this reading.
    private static Optional<ParsedPackage> parseGradlePortalPath(String path) {
        Matcher m = GRADLE_PORTAL_PATTERN.matcher(path);
        if (!m.matches() || !hasArtifactExtension(m.group(4))
                || !fileRepeatsCoordinates(m.group(4), m.group(2), m.group(3))) {
            return Optional.empty();
        }
        return Optional.of(new ParsedPackage(m.group(1) + ":" + m.group(2), m.group(3), ECOSYSTEM));
    }

    static boolean isClient(HttpHeaders headers) {
        return ClientHeaders.userAgentStartsWith(headers, USER_AGENT_PREFIXES);
    }

    // "{g1}/…/{gn}/{artifactId}/{version}/{file}", parsed by string splitting like the npmjs
    // tarball layout. At least one groupId segment is required, and the file must repeat
    // "{artifactId}-{version}" : this rejects any non-Maven resource that merely has the shape.
    private static Optional<ParsedPackage> parseCoordinates(String rest) {
        if (!hasArtifactExtension(rest)) {
            return Optional.empty();
        }
        int fileSlash = rest.lastIndexOf('/');
        int versionSlash = fileSlash > 0 ? rest.lastIndexOf('/', fileSlash - 1) : -1;
        int artifactSlash = versionSlash > 0 ? rest.lastIndexOf('/', versionSlash - 1) : -1;
        if (artifactSlash <= 0) {
            return Optional.empty();
        }
        String groupPath = rest.substring(0, artifactSlash);
        String artifactId = rest.substring(artifactSlash + 1, versionSlash);
        String version = rest.substring(versionSlash + 1, fileSlash);
        String file = rest.substring(fileSlash + 1);
        if (artifactId.isEmpty() || version.isEmpty() || groupPath.startsWith("/") || groupPath.contains("//")
                || !fileRepeatsCoordinates(file, artifactId, version)) {
            return Optional.empty();
        }
        return Optional.of(new ParsedPackage(groupPath.replace('/', '.') + ":" + artifactId, version, ECOSYSTEM));
    }

    private static boolean hasArtifactExtension(String path) {
        return ARTIFACT_EXTENSIONS.stream().anyMatch(path::endsWith);
    }

    // "{artifactId}-{version}" followed by the extension or a "-{classifier}" ("-sources.jar"). A
    // "X-SNAPSHOT" directory holds timestamped files ("lib-1.0-20240101.123456-1.jar") as well as
    // "lib-1.0-SNAPSHOT.jar" : only "{artifactId}-X-" is required then.
    private static boolean fileRepeatsCoordinates(String file, String artifactId, String version) {
        if (version.endsWith("-" + SNAPSHOT_QUALIFIER)) {
            String base = version.substring(0, version.length() - SNAPSHOT_QUALIFIER.length());
            return file.startsWith(artifactId + "-" + base);
        }
        String expected = artifactId + "-" + version;
        if (!file.startsWith(expected)) {
            return false;
        }
        // Exactly an extension, not any '.' : "lib-1.0.1.jar" must not pass as version "1.0".
        String rest = file.substring(expected.length());
        return rest.startsWith("-") || ARTIFACT_EXTENSIONS.contains(rest);
    }
}
