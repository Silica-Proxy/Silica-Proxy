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


package com.silicaproxy.dao.npm;

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** A dateless row identifies its tarball but never answers a publish-date lookup. */
class NpmTarballIndexDaoPublishedAtTest extends BaseIntegrationTest {

    private final NpmTarballIndexDao dao;
    private final JdbcClient jdbcClient;

    @Autowired
    NpmTarballIndexDaoPublishedAtTest(NpmTarballIndexDao dao, JdbcClient jdbcClient) {
        this.dao = dao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanTable() {
        jdbcClient.sql("TRUNCATE npm_tarball_index").update();
    }

    @Test
    void datelessRowShouldIdentifyTarballButNotProvideMetadata() {
        String url = "https://blobs.private.example/sha256/0123abcd";
        dao.save(url, "internal-lib", "1.2.3", null, false, null, "https://private.example/internal-lib",
                Instant.now().plus(1, ChronoUnit.HOURS));

        assertThat(dao.findByUrl(url)).get()
                .extracting(NpmTarballIndexDao.NpmTarballEntry::packageName).isEqualTo("internal-lib");
        assertThat(dao.findMetadataByPackage("internal-lib", "1.2.3")).isEmpty();
    }

    @Test
    void datedRowShouldProvideMetadata() {
        Instant publishedAt = Instant.parse("2021-02-20T15:42:16Z");
        dao.save("https://npm.jsr.io/~/11/@jsr/std__path/1.0.8.tgz", "@jsr/std__path", "1.0.8", publishedAt,
                false, null, "https://npm.jsr.io/@jsr/std__path", Instant.now().plus(1, ChronoUnit.HOURS));

        assertThat(dao.findMetadataByPackage("@jsr/std__path", "1.0.8")).get()
                .extracting(m -> m.publishedAt()).isEqualTo(publishedAt);
    }
}
