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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

class PackageSearchControllerTest extends BaseIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestClient restClient = RestClient.create();
    private final JdbcClient jdbcClient;

    @Autowired
    PackageSearchControllerTest(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldFindPackageAcrossAllThreeSources() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '*', 'WHITELIST', 'Approved', 'admin')
                """).update();
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('GHSA-x', 'OSV', 'lodash', 'npm', 'Old bug', '["4.0.0"]'::jsonb, 5.0)
                """).update();
        jdbcClient.sql("""
                INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
                VALUES ('lodash', 'npm', '4.17.21', true, 'OSV_LIVE', CURRENT_TIMESTAMP + INTERVAL '1 day')
                """).update();

        ResponseEntity<String> response = restClient.get()
                .uri("http://localhost:" + port + "/api/packages/search?packageName=lodash")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"companyPolicies\"");
        assertThat(body).contains("\"WHITELIST\"");
        assertThat(body).contains("\"publicVulnerabilities\"");
        assertThat(body).contains("\"OSV\"");
        assertThat(body).contains("\"apiCacheEntries\"");
        assertThat(body).contains("\"OSV_LIVE\"");
    }

    @Test
    void shouldRejectBothVersionAndVersionRegexTogether() {
        ResponseEntity<String> response = getResponse(
                "/api/packages/search?packageName=lodash&version=1.0.0&versionRegex=^1\\.");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("either 'version'");
    }

    @Test
    void shouldRejectInvalidRegex() {
        ResponseEntity<String> response = getResponse(
                "/api/packages/search?packageName=lodash&versionRegex=[invalid(");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("Invalid versionRegex");
    }

    @Test
    void shouldReturnEmptyListsWhenNothingMatches() {
        ResponseEntity<String> response = getResponse("/api/packages/search?packageName=does-not-exist");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"companyPolicies\":[]");
        assertThat(response.getBody()).contains("\"publicVulnerabilities\":[]");
        assertThat(response.getBody()).contains("\"apiCacheEntries\":[]");
    }

    private ResponseEntity<String> getResponse(String path) {
        try {
            return restClient.get()
                    .uri("http://localhost:" + port + path)
                    .retrieve()
                    .toEntity(String.class);
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        }
    }
}
