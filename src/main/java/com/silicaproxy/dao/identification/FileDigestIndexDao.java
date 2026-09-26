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

import com.silicaproxy.model.dto.HashType;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Persistence of the file digests identified through deps.dev
 * ({@code ResponseIdentificationService}), shared by all proxy instances and consulted before
 * deps.dev. Only identified digests are stored, and never expire : a digest always designates the
 * same file.
 */
@Repository
@NullMarked
public class FileDigestIndexDao {

    private final JdbcClient jdbcClient;

    public FileDigestIndexDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** Package version a file digest was identified as. */
    public record DigestEntry(String ecosystem, String packageName, String version) {}

    /**
     * @param hex lower-case hex digest
     */
    public Optional<DigestEntry> find(HashType type, String hex) {
        return jdbcClient.sql(
                "SELECT ecosystem, package_name, package_version FROM file_digest_index " +
                "WHERE hash_type = ? AND digest = ?"
        )
                .param(type.name())
                .param(hex)
                .query((rs, rowNum) -> new DigestEntry(
                        rs.getString("ecosystem"),
                        rs.getString("package_name"),
                        rs.getString("package_version")
                ))
                .optional();
    }

    /**
     * Remembers an identified digest. A digest already stored is left untouched.
     *
     * @param hex lower-case hex digest
     */
    public void save(HashType type, String hex, String ecosystem, String packageName, String version) {
        jdbcClient.sql(
                "INSERT INTO file_digest_index (hash_type, digest, ecosystem, package_name, package_version) " +
                "VALUES (?, ?, ?, ?, ?) " +
                "ON CONFLICT (hash_type, digest) DO NOTHING"
        )
                .param(type.name())
                .param(hex)
                .param(ecosystem)
                .param(packageName)
                .param(version)
                .update();
    }
}
