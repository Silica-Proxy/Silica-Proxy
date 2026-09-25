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
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** {@link NpmPackumentIndex#relayAndIndex} : body relayed byte for byte, indexed only under the cap. */
class NpmPackumentIndexRelayTest {

    private static final String TARBALL = "https://mirror.internal/blobs/abc.tgz";
    private static final byte[] PACKUMENT = ("{\"name\":\"evil\",\"versions\":{\"1.0.0\":{\"dist\":{\"tarball\":\""
            + TARBALL + "\"}}}}").getBytes(StandardCharsets.UTF_8);

    private static NpmPackumentIndex index(boolean enabled, long maxBodyBytes) {
        return new NpmPackumentIndex(new JsonMapper(),
                new NpmPackumentIndexProperties(enabled, 1000, 60, maxBodyBytes, UnidentifiedTarballAction.ALLOW),
                mock(NpmTarballIndexDao.class));
    }

    private static byte[] relay(NpmPackumentIndex index, byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        index.relayAndIndex(new ByteArrayInputStream(body), null, "https://mirror.internal/evil", out);
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
}
