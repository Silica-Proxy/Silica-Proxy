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

package com.silicaproxy.controller;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.dao.policy.MetadataCacheDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ExternalValidationCacheControllerTest extends BaseIntegrationTest {

    private static final String PATH = "/api/external-validation/cache";

    @LocalServerPort
    private int port;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private ExternalValidationVerdictsDao verdictsDao;

    @Autowired
    private MetadataCacheDao metadataCacheDao;

    @Autowired
    private JdbcClient jdbcClient;

    private final RestClient restClient = RestClient.create();

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldEvictEveryExternalValidationEntryOfTheVersionOnly() {
        Instant later = Instant.now().plus(1, ChronoUnit.HOURS);
        // Target version : sync ALLOWED, async PENDING, permanent BLOCKED verdict, cached chain ALLOW
        cacheDao.upsertPendingSync("svc-sync", "lodash", "npm", "4.17.21", later);
        cacheDao.updateToAllowed("svc-sync", "lodash", "npm", "4.17.21", "ok", later);
        cacheDao.upsertPendingAsync(UUID.randomUUID(), "svc-async", "lodash", "npm", "4.17.21", later);
        verdictsDao.save("svc-other", "lodash", "npm", "4.17.21", "malware");
        metadataCacheDao.saveApiCache("lodash", "npm", "4.17.21", true, "EXTERNAL_VALIDATION_CHAIN", later);
        // Other version / ecosystem : kept
        cacheDao.upsertPendingSync("svc-sync", "lodash", "npm", "4.17.20", later);
        verdictsDao.save("svc-other", "lodash", "npm", "4.17.20", "malware");
        metadataCacheDao.saveApiCache("lodash", "npm", "4.17.20", true, "EXTERNAL_VALIDATION_CHAIN", later);
        cacheDao.upsertPendingSync("svc-sync", "lodash", "maven", "4.17.21", later);

        ResponseEntity<String> response = delete("?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .contains("\"externalValidationCache\":2")
                .contains("\"externalValidationVerdicts\":1")
                .contains("\"apiCache\":1");
        assertThat(cacheDao.findByServiceAndPackage("svc-sync", "lodash", "npm", "4.17.21")).isEmpty();
        assertThat(cacheDao.findByServiceAndPackage("svc-async", "lodash", "npm", "4.17.21")).isEmpty();
        assertThat(verdictsDao.findAllByPackage("lodash", "npm", "4.17.21")).isEmpty();
        assertThat(apiCacheCount("4.17.21")).isZero();

        assertThat(cacheDao.findByServiceAndPackage("svc-sync", "lodash", "npm", "4.17.20")).isPresent();
        assertThat(cacheDao.findByServiceAndPackage("svc-sync", "lodash", "maven", "4.17.21")).isPresent();
        assertThat(verdictsDao.findAllByPackage("lodash", "npm", "4.17.20")).hasSize(1);
        assertThat(apiCacheCount("4.17.20")).isEqualTo(1);
    }

    @Test
    void shouldKeepCachedBlockFromOtherSources() {
        Instant later = Instant.now().plus(1, ChronoUnit.HOURS);
        metadataCacheDao.saveApiCache("lodash", "npm", "4.17.21", false, "OSV", later);

        ResponseEntity<String> response = delete("?ecosystem=npm&packageName=lodash&version=4.17.21");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"apiCache\":0");
        assertThat(apiCacheCount("4.17.21")).isEqualTo(1);
    }

    @Test
    void shouldNormalizePypiNameAndEcosystem() {
        Instant later = Instant.now().plus(1, ChronoUnit.HOURS);
        cacheDao.upsertPendingSync("svc-sync", "py-yaml", "pypi", "6.0.2", later);

        ResponseEntity<String> response = delete("?ecosystem=PyPI&packageName=Py_YAML&version=6.0.2");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"externalValidationCache\":1");
        assertThat(cacheDao.findByServiceAndPackage("svc-sync", "py-yaml", "pypi", "6.0.2")).isEmpty();
    }

    @Test
    void shouldBeIdempotentWhenNothingIsCached() {
        ResponseEntity<String> response = delete("?ecosystem=npm&packageName=lodash&version=1.0.0");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .contains("\"externalValidationCache\":0")
                .contains("\"externalValidationVerdicts\":0")
                .contains("\"apiCache\":0");
    }

    @Test
    void shouldReturn400ForUnsupportedEcosystem() {
        assertThat(delete("?ecosystem=cargo&packageName=serde&version=1.0.0").getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void shouldReturn400WhenParameterMissingOrBlank() {
        assertThat(delete("?ecosystem=npm&packageName=lodash").getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(delete("?ecosystem=npm&packageName=&version=1.0.0").getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    private int apiCacheCount(String version) {
        return jdbcClient.sql("SELECT COUNT(*) FROM api_cache WHERE package_name = 'lodash' AND package_version = :v")
                .param("v", version)
                .query(Integer.class)
                .single();
    }

    private ResponseEntity<String> delete(String query) {
        try {
            return restClient.delete()
                    .uri("http://localhost:" + port + PATH + query)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }
}
