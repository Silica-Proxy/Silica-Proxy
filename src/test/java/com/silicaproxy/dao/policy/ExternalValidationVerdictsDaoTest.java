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


package com.silicaproxy.dao.policy;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.entity.ExternalValidationVerdictEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ExternalValidationVerdictsDaoTest extends BaseIntegrationTest {

    private final ExternalValidationVerdictsDao dao;
    private final JdbcClient jdbcClient;

    @Autowired
    ExternalValidationVerdictsDaoTest(ExternalValidationVerdictsDao dao, JdbcClient jdbcClient) {
        this.dao = dao;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
    }

    @Test
    void findByServiceAndPackage_noEntry_returnsEmpty() {
        Optional<ExternalValidationVerdictEntry> result =
                dao.findByServiceAndPackage("svc", "lodash", "npm", "4.17.21");
        assertThat(result).isEmpty();
    }

    @Test
    void save_insertsNewVerdict() {
        dao.save("test-scanner", "lodash", "npm", "4.17.21", "Malicious dependency chain");

        Optional<ExternalValidationVerdictEntry> result =
                dao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        ExternalValidationVerdictEntry entry = result.get();
        assertThat(entry.serviceName()).isEqualTo("test-scanner");
        assertThat(entry.packageName()).isEqualTo("lodash");
        assertThat(entry.ecosystem()).isEqualTo("npm");
        assertThat(entry.packageVersion()).isEqualTo("4.17.21");
        assertThat(entry.reason()).isEqualTo("Malicious dependency chain");
        assertThat(entry.createdAt()).isNotNull();
    }

    @Test
    void save_onConflict_doesNothingKeepsOriginalReason() {
        dao.save("test-scanner", "lodash", "npm", "4.17.21", "First reason");
        dao.save("test-scanner", "lodash", "npm", "4.17.21", "Second reason");

        long count = jdbcClient.sql("SELECT COUNT(*) FROM external_validation_verdicts")
                .query(Long.class).single();
        assertThat(count).isEqualTo(1);

        Optional<ExternalValidationVerdictEntry> result =
                dao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(result.get().reason()).isEqualTo("First reason");
    }

    @Test
    void save_nullReason_isAccepted() {
        dao.save("test-scanner", "lodash", "npm", "4.17.21", null);

        Optional<ExternalValidationVerdictEntry> result =
                dao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(result).isPresent();
        assertThat(result.get().reason()).isNull();
    }

    @Test
    void findByServiceAndPackage_differentServices_areIndependent() {
        dao.save("scanner-a", "lodash", "npm", "4.17.21", "Blocked by A");

        assertThat(dao.findByServiceAndPackage("scanner-a", "lodash", "npm", "4.17.21")).isPresent();
        assertThat(dao.findByServiceAndPackage("scanner-b", "lodash", "npm", "4.17.21")).isEmpty();
    }

    @Test
    void findByServiceAndPackage_differentVersions_areIndependent() {
        dao.save("test-scanner", "lodash", "npm", "4.17.21", "Blocked");

        assertThat(dao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21")).isPresent();
        assertThat(dao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.20")).isEmpty();
    }

    @Test
    void verdictHasNoTtl_remainsForever() {
        dao.save("test-scanner", "lodash", "npm", "4.17.21", "Permanent block");

        // The verdicts table has no expires_at — entry persists indefinitely
        long count = jdbcClient.sql(
                "SELECT COUNT(*) FROM external_validation_verdicts WHERE service_name='test-scanner'")
                .query(Long.class).single();
        assertThat(count).isEqualTo(1);

        // Verify no expires_at column exists in the table
        long colCount = jdbcClient.sql("""
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name='external_validation_verdicts' AND column_name='expires_at'
            """).query(Long.class).single();
        assertThat(colCount).isEqualTo(0);
    }
}
