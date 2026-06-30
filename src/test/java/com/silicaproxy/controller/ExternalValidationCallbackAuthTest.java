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
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

// The api-key configured for a service (services.<name>.api-key) is also enforced on the
// way IN: the callback must present it as `Authorization: Bearer <api-key>`. This stays
// optional — a service with no api-key configured doesn't require any header at all.
class ExternalValidationCallbackAuthTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private JdbcClient jdbcClient;

    private RestClient restClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");

        registry.add("silicaproxy.external-validation.services.keyed-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.keyed-scanner.url", () -> "http://localhost:0/x");
        registry.add("silicaproxy.external-validation.services.keyed-scanner.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.keyed-scanner.api-key", () -> "secret-callback-key");
        registry.add("silicaproxy.external-validation.services.keyed-scanner.cache-ttl-minutes", () -> "60");

        registry.add("silicaproxy.external-validation.services.no-key-scanner.enabled", () -> "true");
        registry.add("silicaproxy.external-validation.services.no-key-scanner.url", () -> "http://localhost:0/y");
        registry.add("silicaproxy.external-validation.services.no-key-scanner.mode", () -> "async");
        registry.add("silicaproxy.external-validation.services.no-key-scanner.cache-ttl-minutes", () -> "60");
    }

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        restClient = RestClient.create("http://localhost:" + port);
    }

    @Test
    void callback_correctApiKey_isProcessed() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "keyed-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        ResponseEntity<Void> response = restClient.post()
                .uri("/external-validation/callback/" + token)
                .header("Authorization", "Bearer secret-callback-key")
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"ALLOWED\"}")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void callback_wrongApiKey_returns401AndLeavesEntryPending() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "keyed-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        try {
            restClient.post()
                    .uri("/external-validation/callback/" + token)
                    .header("Authorization", "Bearer wrong-key")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"verdict\":\"ALLOWED\"}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 401");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("keyed-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("PENDING");
    }

    @Test
    void callback_missingAuthorizationHeader_returns401WhenApiKeyConfigured() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "keyed-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        try {
            restClient.post()
                    .uri("/external-validation/callback/" + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"verdict\":\"ALLOWED\"}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 401");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    // Optional, not mandatory: a service with no api-key configured accepts callbacks
    // with no Authorization header at all — fully backward compatible.
    @Test
    void callback_noApiKeyConfigured_noAuthorizationHeaderRequired() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "no-key-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        ResponseEntity<Void> response = restClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"ALLOWED\"}")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
