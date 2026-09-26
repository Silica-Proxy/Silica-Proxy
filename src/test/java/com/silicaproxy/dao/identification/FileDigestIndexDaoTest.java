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

package com.silicaproxy.dao.identification;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.identification.FileDigestIndexDao.DigestEntry;
import com.silicaproxy.model.dto.HashType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;

class FileDigestIndexDaoTest extends BaseIntegrationTest {

    private static final String SHA1 = "7cf2726fdcfbc8610f9a71fb3ed639871f315340";

    private final FileDigestIndexDao dao;
    private final JdbcClient jdbcClient;

    @Autowired
    FileDigestIndexDaoTest(FileDigestIndexDao dao, JdbcClient jdbcClient) {
        this.dao = dao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanTable() {
        jdbcClient.sql("TRUNCATE file_digest_index").update();
    }

    @Test
    void shouldFindSavedDigest() {
        dao.save(HashType.SHA1, SHA1, "maven", "org.slf4j:slf4j-api", "2.0.9");

        assertThat(dao.find(HashType.SHA1, SHA1)).contains(new DigestEntry("maven", "org.slf4j:slf4j-api", "2.0.9"));
    }

    @Test
    void shouldNotFindUnknownDigest() {
        assertThat(dao.find(HashType.SHA1, SHA1)).isEmpty();
    }

    @Test
    void shouldKeepFirstEntryWhenDigestSavedTwice() {
        dao.save(HashType.SHA1, SHA1, "maven", "org.slf4j:slf4j-api", "2.0.9");
        dao.save(HashType.SHA1, SHA1, "npm", "other", "1.0.0");

        assertThat(dao.find(HashType.SHA1, SHA1)).contains(new DigestEntry("maven", "org.slf4j:slf4j-api", "2.0.9"));
        assertThat(jdbcClient.sql("SELECT COUNT(*) FROM file_digest_index").query(Integer.class).single()).isEqualTo(1);
    }

    @Test
    void shouldKeepDigestTypesApart() {
        String sameHex = "ab".repeat(20);
        dao.save(HashType.SHA1, sameHex, "maven", "org.example:lib", "1.0.0");

        assertThat(dao.find(HashType.SHA256, sameHex)).isEmpty();
    }
}
