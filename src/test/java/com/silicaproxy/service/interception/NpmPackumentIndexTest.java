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
import com.silicaproxy.dao.npm.NpmTarballIndexDao;
import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class NpmPackumentIndexTest {

    private static final String JSR_PACKUMENT = """
            {
              "name": "@jsr/zerun__group-deps",
              "dist-tags": {"latest": "0.1.5"},
              "time": {"created": "2026-02-13T12:30:09.940Z", "modified": "2026-02-13T14:12:42.259Z",
                       "0.1.4": "2026-02-13T14:20:00.000Z", "0.1.5": "2026-02-13T15:30:28.752Z"},
              "versions": {
                "0.1.4": {"name": "@jsr/zerun__group-deps", "version": "0.1.4",
                          "dist": {"tarball": "https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.4.tgz"}},
                "0.1.5": {"name": "@jsr/zerun__group-deps", "version": "0.1.5",
                          "dist": {"tarball": "https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz"}}
              }
            }
            """;

    private static NpmPackumentIndex newIndex(int maxEntries) {
        return new NpmPackumentIndex(new JsonMapper(),
                new NpmPackumentIndexProperties(true, maxEntries, 60, 1024 * 1024, UnidentifiedTarballAction.ALLOW),
                mock(NpmTarballIndexDao.class));
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void shouldResolveTarballUrlLearnedFromPackumentWhateverTheLayout() {
        NpmPackumentIndex index = newIndex(1000);

        assertThat(index.indexPackument(utf8(JSR_PACKUMENT), null, "")).isEqualTo(2);

        Optional<ParsedPackage> hit = index.lookup("https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz");
        assertThat(hit).isPresent();
        assertThat(hit.get().packageName()).isEqualTo("@jsr/zerun__group-deps");
        assertThat(hit.get().version()).isEqualTo("0.1.5");
        assertThat(hit.get().ecosystem()).isEqualTo("npm");
    }

    @Test
    void shouldMatchPlainHttpRequestAgainstHttpsTarballUrl() {
        NpmPackumentIndex index = newIndex(1000);
        index.indexPackument(utf8(JSR_PACKUMENT), null, "");

        // The controller sees "http://host/..." before convertToHttpsIfNeeded ; host case differs too.
        assertThat(index.lookup("http://NPM.jsr.io/~/11/@jsr/zerun__group-deps/0.1.4.tgz")).isPresent();
        assertThat(index.lookup("https://npm.jsr.io:443/~/11/@jsr/zerun__group-deps/0.1.4.tgz")).isPresent();
    }

    @Test
    void shouldMissUnknownTarballAndUnparseableUrl() {
        NpmPackumentIndex index = newIndex(1000);
        index.indexPackument(utf8(JSR_PACKUMENT), null, "");

        assertThat(index.lookup("https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.6.tgz")).isEmpty();
        assertThat(index.lookup("not a url at all")).isEmpty();
        assertThat(index.lookup("/relative/path.tgz")).isEmpty();
    }

    @Test
    void shouldDecodeGzipEncodedBody() throws IOException {
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
            out.write(utf8(JSR_PACKUMENT));
        }
        NpmPackumentIndex index = newIndex(1000);

        assertThat(index.indexPackument(gz.toByteArray(), "gzip", "")).isEqualTo(2);
        assertThat(index.lookup("https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz")).isPresent();
    }

    @Test
    void shouldIgnoreNonPackumentBodies() {
        NpmPackumentIndex index = newIndex(1000);

        assertThat(index.indexPackument(utf8("{\"objects\":[],\"total\":0}"), null, "")).isZero();   // search
        assertThat(index.indexPackument(utf8("{\"latest\":\"1.0.0\"}"), null, "")).isZero();          // dist-tags
        assertThat(index.indexPackument(utf8("<html>not json</html>"), null, "")).isZero();
        assertThat(index.indexPackument(utf8("{\"versions\":"), null, "")).isZero();                  // truncated
        assertThat(index.indexPackument(utf8(JSR_PACKUMENT), "br", "")).isZero();                     // unsupported
        assertThat(index.size()).isZero();
    }

    @Test
    void shouldFallBackToTopLevelNameAndVersionKeyWhenManifestOmitsThem() {
        NpmPackumentIndex index = newIndex(1000);
        String body = """
                {"name": "lodash", "versions": {"4.17.21": {"dist": {"tarball": "https://mirror.internal/x/y/z.tgz"}}}}
                """;

        assertThat(index.indexPackument(utf8(body), null, "")).isEqualTo(1);
        ParsedPackage hit = index.lookup("https://mirror.internal/x/y/z.tgz").orElseThrow();
        assertThat(hit.packageName()).isEqualTo("lodash");
        assertThat(hit.version()).isEqualTo("4.17.21");
    }

    @Test
    void shouldEvictExpiredEntriesAndEnforceSizeCap() {
        NpmPackumentIndex index = newIndex(1);
        index.indexPackument(utf8(JSR_PACKUMENT), null, "");
        assertThat(index.size()).isEqualTo(1);

        assertThat(index.evictStaleEntries(Duration.ofMinutes(60))).isZero();
        assertThat(index.evictStaleEntries(Duration.ZERO.minusSeconds(1))).isEqualTo(1);
        assertThat(index.size()).isZero();
    }

    @Test
    void shouldBeInertWhenDisabled() {
        NpmPackumentIndex index = new NpmPackumentIndex(new JsonMapper(),
                new NpmPackumentIndexProperties(false, 1000, 60, 1024 * 1024, UnidentifiedTarballAction.ALLOW),
                mock(NpmTarballIndexDao.class));

        assertThat(index.isEnabled()).isFalse();
        assertThat(index.indexPackument(utf8(JSR_PACKUMENT), null, "")).isZero();
        assertThat(index.lookup("https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz")).isEmpty();
    }

    // --- Publish date / deprecation learned from the packument ---

    @Test
    void shouldExposePublishDateAndDeprecationFromPackument() {
        NpmPackumentIndex index = newIndex(1000);
        index.indexPackument(utf8(JSR_PACKUMENT), null, "");

        Optional<PackageMetadataResult> meta = index.metadata("@jsr/zerun__group-deps", "0.1.5");
        assertThat(meta).isPresent();
        assertThat(meta.get().publishedAt()).isEqualTo(Instant.parse("2026-02-13T15:30:28.752Z"));
        assertThat(meta.get().isDeprecated()).isFalse();
        assertThat(index.metadata("@jsr/zerun__group-deps", "9.9.9")).isEmpty();
        assertThat(index.metadata("other", "0.1.5")).isEmpty();
    }

    @Test
    void shouldStillIndexTarballsWhenPackumentHasNoTimeEntry() {
        // registry.npmjs.org's abbreviated packument (what npm requests) omits "time".
        NpmPackumentIndex index = newIndex(1000);
        String body = """
                {"name": "lodash", "versions": {"4.17.21": {"dist": {"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}}
                """;

        assertThat(index.indexPackument(utf8(body), null, "")).isEqualTo(1);
        assertThat(index.lookup("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")).isPresent();
        assertThat(index.metadata("lodash", "4.17.21")).isEmpty();
    }

    @Test
    void shouldReadDeprecationAsMessageOrBoolean() {
        NpmPackumentIndex index = newIndex(1000);
        String body = """
                {"name": "p", "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2020-01-02T00:00:00Z", "3.0.0": "2020-01-03T00:00:00Z"},
                 "versions": {
                   "1.0.0": {"deprecated": "use v3", "dist": {"tarball": "https://r/p/1.tgz"}},
                   "2.0.0": {"deprecated": true, "dist": {"tarball": "https://r/p/2.tgz"}},
                   "3.0.0": {"deprecated": "", "dist": {"tarball": "https://r/p/3.tgz"}}}}
                """;
        index.indexPackument(utf8(body), null, "");

        PackageMetadataResult v1 = index.metadata("p", "1.0.0").orElseThrow();
        assertThat(v1.isDeprecated()).isTrue();
        assertThat(v1.deprecationReason()).isEqualTo("use v3");
        PackageMetadataResult v2 = index.metadata("p", "2.0.0").orElseThrow();
        assertThat(v2.isDeprecated()).isTrue();
        assertThat(v2.deprecationReason()).isNull();
        assertThat(index.metadata("p", "3.0.0").orElseThrow().isDeprecated()).isFalse();
    }

    @Test
    void shouldToleratMalformedTimeWithoutLosingTarballs() {
        NpmPackumentIndex index = newIndex(1000);
        String body = """
                {"name": "p", "time": {"1.0.0": "yesterday-ish"},
                 "versions": {"1.0.0": {"dist": {"tarball": "https://r/p/1.tgz"}}}}
                """;

        assertThat(index.indexPackument(utf8(body), null, "")).isEqualTo(1);
        assertThat(index.lookup("https://r/p/1.tgz")).isPresent();
        assertThat(index.metadata("p", "1.0.0")).isEmpty();
    }

    @Test
    void shouldRememberOriginPackumentUrl() {
        NpmPackumentIndex index = newIndex(1000);
        index.indexPackument(utf8(JSR_PACKUMENT), null, "https://npm.jsr.io/@jsr%2fzerun__group-deps");

        assertThat(index.originPackumentUrl("@jsr/zerun__group-deps", "0.1.5"))
                .contains("https://npm.jsr.io/@jsr%2fzerun__group-deps");
        assertThat(index.originPackumentUrl("@jsr/zerun__group-deps", "9.9.9")).isEmpty();

        NpmPackumentIndex withoutOrigin = newIndex(1000);
        withoutOrigin.indexPackument(utf8(JSR_PACKUMENT), null, "");
        assertThat(withoutOrigin.originPackumentUrl("@jsr/zerun__group-deps", "0.1.5")).isEmpty();
    }

    @Test
    void shouldEvictMetadataTogetherWithTarballs() {
        NpmPackumentIndex capped = newIndex(1);
        capped.indexPackument(utf8(JSR_PACKUMENT), null, "");
        assertThat(capped.size()).isEqualTo(1);
        // Exactly one of the two versions survived the cap, and its metadata with it.
        long survivors = java.util.stream.Stream.of("0.1.4", "0.1.5")
                .filter(v -> capped.metadata("@jsr/zerun__group-deps", v).isPresent()).count();
        assertThat(survivors).isEqualTo(1);

        NpmPackumentIndex expiring = newIndex(1000);
        expiring.indexPackument(utf8(JSR_PACKUMENT), null, "");
        expiring.evictStaleEntries(Duration.ZERO.minusSeconds(1));
        assertThat(expiring.metadata("@jsr/zerun__group-deps", "0.1.5")).isEmpty();
        assertThat(expiring.originPackumentUrl("@jsr/zerun__group-deps", "0.1.5")).isEmpty();
    }
}
