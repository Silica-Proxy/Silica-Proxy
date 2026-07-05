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

import com.silicaproxy.config.Metrics;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import com.silicaproxy.model.entity.ExternalValidationVerdictEntry;
import com.silicaproxy.service.decision.ExternalValidationService;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

class ExternalValidationCallbackControllerTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private ExternalValidationVerdictsDao verdictsDao;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private MeterRegistry meterRegistry;

    private RestClient restClient;

    @BeforeEach
    void setUp() {
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        restClient = RestClient.create("http://localhost:" + port);
    }

    // Delta-based read: the registry is shared across every test in this class, so counters
    // persist between tests -- reading a before/after delta is the only order-independent way
    // to assert "this call incremented it by exactly one".
    private double callbackMetricCount(String service, String result) {
        io.micrometer.core.instrument.Counter counter = meterRegistry
                .find(Metrics.CALLBACK_METRIC)
                .tag(Metrics.TAG_SERVICE, service)
                .tag(Metrics.TAG_RESULT, result)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    // Test 11 — valid ALLOWED callback updates cache to ALLOWED
    @Test
    void callback_allowedVerdict_returns200AndUpdatesCache() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        double before = callbackMetricCount("test-scanner", ExternalValidationService.CallbackResult.PROCESSED.name());
        ResponseEntity<Void> response = restClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"ALLOWED\",\"reason\":\"No threats found\"}")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry).isPresent();
        assertThat(entry.get().status()).isEqualTo("ALLOWED");
        assertThat(entry.get().reason()).isEqualTo("No threats found");
        assertThat(entry.get().expiresAt()).isAfter(Instant.now().plus(59, ChronoUnit.MINUTES));
        assertThat(callbackMetricCount("test-scanner", ExternalValidationService.CallbackResult.PROCESSED.name()) - before).isEqualTo(1.0);
    }

    // Test 11b — valid BLOCKED callback removes from cache and writes to verdicts
    @Test
    void callback_blockedVerdict_returns200WritesToVerdictsAndRemovesFromCache() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        double before = callbackMetricCount("test-scanner", ExternalValidationService.CallbackResult.PROCESSED.name());
        ResponseEntity<Void> response = restClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"BLOCKED\",\"reason\":\"Malicious dependency chain\"}")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Cache entry removed (BLOCKED goes to permanent verdicts table)
        assertThat(cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21"))
                .isEmpty();

        // Permanent verdict stored
        Optional<ExternalValidationVerdictEntry> verdict = verdictsDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(verdict).isPresent();
        assertThat(verdict.get().reason()).isEqualTo("Malicious dependency chain");
        assertThat(callbackMetricCount("test-scanner", ExternalValidationService.CallbackResult.PROCESSED.name()) - before).isEqualTo(1.0);
    }

    // Test 12 — unknown token returns 404
    @Test
    void callback_unknownToken_returns404() {
        double before = callbackMetricCount(Metrics.SERVICE_UNKNOWN, ExternalValidationService.CallbackResult.NOT_FOUND.name());
        try {
            restClient.post()
                    .uri("/external-validation/callback/" + UUID.randomUUID())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"verdict\":\"ALLOWED\"}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 404");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
        assertThat(callbackMetricCount(Metrics.SERVICE_UNKNOWN, ExternalValidationService.CallbackResult.NOT_FOUND.name()) - before).isEqualTo(1.0);
    }

    // Test 13 — already resolved token returns 404
    @Test
    void callback_alreadyResolvedToken_returns404() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));
        cacheDao.updateToAllowedByToken(token, null,
                Instant.now().plus(60, ChronoUnit.MINUTES));

        double before = callbackMetricCount("test-scanner", ExternalValidationService.CallbackResult.NOT_FOUND.name());
        try {
            restClient.post()
                    .uri("/external-validation/callback/" + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"verdict\":\"BLOCKED\"}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 404");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
        assertThat(callbackMetricCount("test-scanner", ExternalValidationService.CallbackResult.NOT_FOUND.name()) - before).isEqualTo(1.0);
    }

    // Test 14 — invalid verdict value returns 400
    @Test
    void callback_invalidVerdictValue_returns400() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        try {
            restClient.post()
                    .uri("/external-validation/callback/" + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"verdict\":\"UNKNOWN\",\"reason\":\"something\"}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 400");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    // Test 58 — missing verdict field returns 400
    @Test
    void callback_missingVerdictField_returns400() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        try {
            restClient.post()
                    .uri("/external-validation/callback/" + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"reason\":\"no verdict here\"}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 400");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    // Test 58b — empty body returns 400
    @Test
    void callback_emptyBody_returns400() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        try {
            restClient.post()
                    .uri("/external-validation/callback/" + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{}")
                    .retrieve()
                    .toBodilessEntity();
            fail("Expected 400");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
    }

    // Callback without reason field is accepted (reason is optional)
    @Test
    void callback_withoutReason_isAccepted() {
        UUID token = UUID.randomUUID();
        cacheDao.upsertPendingAsync(token, "test-scanner", "lodash", "npm", "4.17.21",
                Instant.now().plus(30, ChronoUnit.MINUTES));

        ResponseEntity<Void> response = restClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"ALLOWED\"}")
                .retrieve()
                .toBodilessEntity();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByServiceAndPackage("test-scanner", "lodash", "npm", "4.17.21");
        assertThat(entry.get().status()).isEqualTo("ALLOWED");
    }
}
