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


package com.silicaproxy.config;

import com.silicaproxy.BaseIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityConfigurationTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final org.springframework.web.client.RestClient restClient = org.springframework.web.client.RestClient.create();
    private final SsrfValidator ssrfValidator;

    @Autowired
    SecurityConfigurationTest(SsrfValidator ssrfValidator) {
        this.ssrfValidator = ssrfValidator;
    }

    @BeforeEach
    void setUpSsrf() {
        ssrfValidator.setEnabled(true);
    }

    @AfterEach
    void tearDownSsrf() {
        ssrfValidator.setEnabled(false);
    }

    @Test
    void shouldExposeHealthAndPrometheusEndpoints() {
        ResponseEntity<String> healthResponse = restClientGet("/actuator/health");
        assertThat(healthResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Make a call to record metrics on controller and URL parser
        restClientGet("/invalid-path-to-trigger-metrics");

        ResponseEntity<String> prometheusResponse = restClientGet("/actuator/prometheus");
        assertThat(prometheusResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        
        String body = prometheusResponse.getBody();
        assertThat(body).isNotNull();
        // Verify the presence of metrics (dots are converted to underscores by Prometheus)
        assertThat(body).contains("silicaproxy_controller_requests_seconds");
        assertThat(body).contains("silicaproxy_service_urlparser_parseurl_seconds");
    }

    @Test
    void shouldNotExposeEnvOrShutdownEndpoints() {
        ResponseEntity<String> envResponse = restClientGet("/actuator/env");
        assertThat(envResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        ResponseEntity<String> shutdownResponse = restClientPost("/actuator/shutdown");
        assertThat(shutdownResponse.getStatusCode().value())
                .as("POST /actuator/shutdown must be inaccessible (404 or 405)")
                .isIn(HttpStatus.NOT_FOUND.value(), HttpStatus.METHOD_NOT_ALLOWED.value());
    }

    private ResponseEntity<String> restClientGet(String path) {
        try {
            return restClient.get()
                    .uri("http://localhost:" + port + path)
                    .retrieve()
                    .toEntity(String.class);
        } catch (org.springframework.web.client.RestClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    private ResponseEntity<String> restClientPost(String path) {
        try {
            return restClient.post()
                    .uri("http://localhost:" + port + path)
                    .retrieve()
                    .toEntity(String.class);
        } catch (org.springframework.web.client.RestClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }

    @Test
    void shouldBlockSsrfAttempts() {
        assertThatThrownBy(() -> ssrfValidator.validateUrl("http://localhost:8080/admin"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");

        assertThatThrownBy(() -> ssrfValidator.validateUrl("http://127.0.0.1:8080/admin"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");

        assertThatThrownBy(() -> ssrfValidator.validateUrl("http://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");
    }

    @Test
    void shouldBlockPrivateIpRanges() {
        assertThatThrownBy(() -> ssrfValidator.validateUrl("http://10.0.0.5/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");

        assertThatThrownBy(() -> ssrfValidator.validateUrl("http://172.16.0.5/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");

        assertThatThrownBy(() -> ssrfValidator.validateUrl("http://192.168.1.1/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");
    }

    @Test
    void shouldAllowExternalUrls() {
        // Validation of a public URL that is not loopback or link-local
        ssrfValidator.validateUrl("https://registry.npmjs.org/lodash");
    }
}
