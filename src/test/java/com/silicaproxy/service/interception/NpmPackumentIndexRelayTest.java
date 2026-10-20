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

import com.silicaproxy.dao.npm.NpmTarballIndexDao;
import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** {@link NpmPackumentIndex#relayAndIndex} : body relayed byte for byte, indexed only under the cap. */
class NpmPackumentIndexRelayTest {

    private static final String TARBALL = "https://mirror.internal/blobs/abc.tgz";
    private static final byte[] PACKUMENT = ("{\"name\":\"evil\",\"versions\":{\"1.0.0\":{\"dist\":{\"tarball\":\""
            + TARBALL + "\"}}}}").getBytes(StandardCharsets.UTF_8);

    private static NpmPackumentIndex index(boolean enabled, long maxBodyBytes) {
        return index(enabled, maxBodyBytes, 128L * 1024 * 1024, 16);
    }

    private static NpmPackumentIndex index(boolean enabled, long maxBodyBytes, long maxDecodedBytes,
            int maxConcurrentIndexing) {
        return new NpmPackumentIndex(new JsonMapper(),
                new NpmPackumentIndexProperties(enabled, 1000, 60, maxBodyBytes, UnidentifiedTarballAction.ALLOW,
                        maxDecodedBytes, maxConcurrentIndexing),
                mock(NpmTarballIndexDao.class));
    }

    private static byte[] relay(NpmPackumentIndex index, byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        index.relayAndIndex(new ByteArrayInputStream(body), null, -1, "https://mirror.internal/evil", out);
        return out.toByteArray();
    }

    @Test
    void shouldIndexAndRelayBodyUnderCap() throws IOException {
        NpmPackumentIndex index = index(true, 1024 * 1024);

        assertThat(relay(index, PACKUMENT)).isEqualTo(PACKUMENT);
        assertThat(index.lookup(TARBALL)).contains(new ParsedPackage("evil", "1.0.0", "npm"));
        assertThat(index.originPackumentUrl("evil", "1.0.0")).contains("https://mirror.internal/evil");
    }

    @Test
    void shouldRelayWholeBodyWithoutIndexingOverCap() throws IOException {
        // Larger than both the cap and the 16 KB read chunk : prefix buffered, rest streamed.
        StringBuilder padded = new StringBuilder(new String(PACKUMENT, StandardCharsets.UTF_8));
        padded.insert(1, "\"pad\":\"" + "x".repeat(40_000) + "\",");
        byte[] body = padded.toString().getBytes(StandardCharsets.UTF_8);
        NpmPackumentIndex index = index(true, 1024);

        assertThat(relay(index, body)).isEqualTo(body);
        assertThat(index.size()).isZero();
    }

    @Test
    void shouldRelayWithoutIndexingWhenDisabled() throws IOException {
        NpmPackumentIndex index = index(false, 1024 * 1024);

        assertThat(relay(index, PACKUMENT)).isEqualTo(PACKUMENT);
        assertThat(index.size()).isZero();
    }

    @Test
    void shouldRelayGzipBombByteForByteWithoutIndexing() throws IOException {
        String bomb = "{\"name\": \"evil\", \"pad\": [" + "0,".repeat(2 * 1024 * 1024)
                + "0], \"versions\": {\"1.0.0\": {\"dist\": {\"tarball\": \"" + TARBALL + "\"}}}}";
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
            out.write(bomb.getBytes(StandardCharsets.UTF_8));
        }
        byte[] body = gz.toByteArray();
        NpmPackumentIndex index = index(true, 1024 * 1024, 1024 * 1024, 16);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        index.relayAndIndex(new ByteArrayInputStream(body), "gzip", body.length, "https://mirror.internal/evil", out);

        assertThat(out.toByteArray()).isEqualTo(body);
        assertThat(index.size()).isZero();
    }

    @Test
    void shouldRelayWithoutBufferingWhenAnnouncedLengthExceedsCap() throws IOException {
        NpmPackumentIndex index = index(true, 1024);
        byte[] body = new byte[4096];
        System.arraycopy(PACKUMENT, 0, body, 0, PACKUMENT.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        index.relayAndIndex(new ByteArrayInputStream(body), null, body.length, "https://mirror.internal/evil", out);

        assertThat(out.toByteArray()).isEqualTo(body);
        assertThat(index.size()).isZero();
    }

    @Test
    void shouldIndexWithExactContentLength() throws IOException {
        NpmPackumentIndex index = index(true, 1024 * 1024);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        index.relayAndIndex(new ByteArrayInputStream(PACKUMENT), null, PACKUMENT.length, "https://mirror.internal/evil", out);

        assertThat(out.toByteArray()).isEqualTo(PACKUMENT);
        assertThat(index.lookup(TARBALL)).isPresent();
    }

    @Test
    void shouldRelayWithoutIndexingWhenIndexingIsSaturated() throws Exception {
        NpmPackumentIndex index = index(true, 1024 * 1024, 128L * 1024 * 1024, 1);
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // Holds the only permit : its body blocks until released.
        InputStream stalled = new InputStream() {
            @Override
            public int read() throws IOException {
                holding.countDown();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return -1;
            }
        };
        CompletableFuture<Void> first = CompletableFuture.runAsync(() -> {
            try {
                index.relayAndIndex(stalled, null, -1, "https://mirror.internal/stalled", new ByteArrayOutputStream());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        assertThat(holding.await(5, TimeUnit.SECONDS)).isTrue();

        try {
            assertThat(relay(index, PACKUMENT)).isEqualTo(PACKUMENT);
            assertThat(index.lookup(TARBALL)).isEmpty();
        } finally {
            release.countDown();
            first.get(5, TimeUnit.SECONDS);
        }
        // The permit is back : the next packument is indexed again.
        assertThat(relay(index, PACKUMENT)).isEqualTo(PACKUMENT);
        assertThat(index.lookup(TARBALL)).isPresent();
    }
}
