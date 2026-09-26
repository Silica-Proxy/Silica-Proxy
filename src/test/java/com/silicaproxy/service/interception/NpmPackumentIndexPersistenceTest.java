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

import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
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

    private static byte[] abbreviatedPackument(String name, String version, String tarball) {
        return ("{\"name\":\"" + name + "\",\"versions\":{\"" + version + "\":{\"version\":\"" + version + "\","
                + "\"dist\":{\"tarball\":\"" + tarball + "\"}}}}").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void shouldPersistDatelessEntryWhenTarballUrlIsUnidentifiable() {
        String tarball = "https://blobs.private.example/sha256/0123abcd";

        index().indexPackument(
                abbreviatedPackument("internal-lib", "1.2.3", tarball), null, "https://private.example/internal-lib");

        verify(dao).save(eq(tarball), eq("internal-lib"), eq("1.2.3"), isNull(), anyBoolean(), any(),
                eq("https://private.example/internal-lib"), any());
    }

    @Test
    void shouldNotPersistDatelessEntryWhenTarballUrlIsIdentifiable() {
        index().indexPackument(
                abbreviatedPackument("lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
                null, "https://registry.npmjs.org/lodash");

        verify(dao, never()).save(anyString(), anyString(), anyString(), any(), anyBoolean(), any(), anyString(), any());
    }

    @Test
    void shouldKeepPersistingDatedEntryWhateverTheLayout() {
        String packument = "{\"name\":\"lodash\",\"time\":{\"4.17.21\":\"2021-02-20T15:42:16.891Z\"},"
                + "\"versions\":{\"4.17.21\":{\"version\":\"4.17.21\","
                + "\"dist\":{\"tarball\":\"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\"}}}}";

        index().indexPackument(packument.getBytes(StandardCharsets.UTF_8), null, "");

        verify(dao).save(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"), eq("lodash"), eq("4.17.21"),
                any(), anyBoolean(), any(), anyString(), any());
    }
}
