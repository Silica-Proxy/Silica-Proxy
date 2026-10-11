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
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * An index entry without a publish date is shared through the database only when the tarball
 * URL cannot be identified by the URL parser : otherwise a tarball request landing on another
 * instance would bypass the security check.
 */
class NpmPackumentIndexPersistenceTest {

    private final NpmTarballIndexDao dao = mock(NpmTarballIndexDao.class);

    private NpmPackumentIndex index() {
        return new NpmPackumentIndex(new JsonMapper(),
                new NpmPackumentIndexProperties(true, 1000, 60, 1024 * 1024, UnidentifiedTarballAction.ALLOW), dao);
    }

    @SuppressWarnings("unchecked")
    private List<NpmTarballIndexDao.PendingEntry> savedEntries() {
        ArgumentCaptor<List<NpmTarballIndexDao.PendingEntry>> captor = ArgumentCaptor.forClass(List.class);
        verify(dao).saveAll(captor.capture());
        return captor.getValue();
    }

    private static byte[] abbreviatedPackument(String name, String version, String tarball) {
        return ("{\"name\":\"" + name + "\",\"versions\":{\"" + version + "\":{\"version\":\"" + version + "\","
                + "\"dist\":{\"tarball\":\"" + tarball + "\"}}}}").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void shouldPersistDatelessEntryWhenTarballUrlIsUnidentifiable() {
        String tarball = "https://blobs.private.example/sha256/0123abcd";

        index().indexPackument(
                abbreviatedPackument("internal-lib", "1.2.3", tarball), null, "https://private.example/internal-lib");

        List<NpmTarballIndexDao.PendingEntry> saved = savedEntries();
        assertThat(saved).hasSize(1);
        NpmTarballIndexDao.NpmTarballEntry entry = saved.get(0).entry();
        assertThat(entry.tarballUrl()).isEqualTo(tarball);
        assertThat(entry.packageName()).isEqualTo("internal-lib");
        assertThat(entry.packageVersion()).isEqualTo("1.2.3");
        assertThat(entry.publishedAt()).isNull();
        assertThat(entry.packumentUrl()).isEqualTo("https://private.example/internal-lib");
    }

    @Test
    void shouldNotPersistDatelessEntryWhenTarballUrlIsIdentifiable() {
        index().indexPackument(
                abbreviatedPackument("lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
                null, "https://registry.npmjs.org/lodash");

        verify(dao, never()).saveAll(any());
    }

    @Test
    void shouldKeepPersistingDatedEntryWhateverTheLayout() {
        String packument = "{\"name\":\"lodash\",\"time\":{\"4.17.21\":\"2021-02-20T15:42:16.891Z\"},"
                + "\"versions\":{\"4.17.21\":{\"version\":\"4.17.21\","
                + "\"dist\":{\"tarball\":\"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\"}}}}";

        index().indexPackument(packument.getBytes(StandardCharsets.UTF_8), null, "");

        List<NpmTarballIndexDao.PendingEntry> saved = savedEntries();
        assertThat(saved).hasSize(1);
        assertThat(saved.get(0).entry().tarballUrl()).isEqualTo("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");
        assertThat(saved.get(0).entry().publishedAt()).isNotNull();
    }

    @Test
    void shouldPersistIdentificationEntryBeforeTheClientGetsTheBody() throws Exception {
        String tarball = "https://blobs.private.example/sha256/0123abcd";
        byte[] body = abbreviatedPackument("internal-lib", "1.2.3", tarball);
        boolean[] persistedWhenFirstByteWritten = new boolean[1];
        OutputStream out = new ByteArrayOutputStream() {
            @Override
            public synchronized void write(byte[] b, int off, int len) {
                persistedWhenFirstByteWritten[0] = Mockito.mockingDetails(dao).getInvocations().stream()
                        .anyMatch(invocation -> invocation.getMethod().getName().equals("saveAll"));
                super.write(b, off, len);
            }
        };

        index().relayAndIndex(new ByteArrayInputStream(body), null, "https://private.example/internal-lib", out);

        assertThat(persistedWhenFirstByteWritten[0]).isTrue();
    }
}
