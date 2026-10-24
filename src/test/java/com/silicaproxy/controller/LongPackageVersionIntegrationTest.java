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
import com.silicaproxy.dao.audit.ApiCallLogDao;
import com.silicaproxy.dao.client.ProxyStreamClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Issue #110 : a version longer than the former VARCHAR(50) columns (npm allows up to 256
 * characters) must be decided and audited like any other, instead of failing the insert with a
 * 500 and losing the audit row and the api_call_log batch.
 */
@TestPropertySource(properties = "silicaproxy.api-call-log.enabled=true")
class LongPackageVersionIntegrationTest extends BaseIntegrationTest {

    // 120 characters : a semver prerelease with a long build identifier, as seen on npm.
    private static final String LONG_VERSION = "1.0.0-" + "nightly.20261024.".repeat(6) + "a".repeat(12);

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ApiCallLogDao apiCallLogDao;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @BeforeEach
    void setUp() {
        jdbcClient.sql("DELETE FROM company_policies").update();
        jdbcClient.sql("DELETE FROM public_vulnerabilities").update();
        jdbcClient.sql("DELETE FROM api_cache").update();
        jdbcClient.sql("DELETE FROM package_metadata").update();
        wireMock.resetAll();

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        this.proxyRestClient = RestClient.builder().requestFactory(factory).build();
    }

    @Test
    void longVersionIsOneHundredTwentyCharacters() {
        assertThat(LONG_VERSION).hasSize(120);
    }

    @Test
    void shouldWidenEveryVersionColumnTo256() {
        List<Map<String, Object>> columns = jdbcClient.sql("""
                SELECT table_name, column_name, character_maximum_length
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name IN ('api_cache', 'package_metadata', 'proxy_audit_logs', 'api_call_log',
                                     'external_validation_cache', 'external_validation_verdicts',
                                     'npm_tarball_index', 'company_policies')
                  AND column_name IN ('package_version', 'version_pattern')
                """).query().listOfRows();

        assertThat(columns).hasSize(8);
        assertThat(columns).allSatisfy(column ->
                assertThat(column.get("character_maximum_length")).as(column.get("table_name") + "." + column.get("column_name"))
                        .isEqualTo(256));
    }

    @Test
    void shouldAllowAndAuditLongVersionThroughOsvLiveChain() throws Exception {
        String name = "long-version-pkg";
        Instant publishedAt = Instant.now().minus(30, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/" + name))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"time\": {\"" + LONG_VERSION + "\": \"" + publishedAt + "\"},"
                                + " \"versions\": {\"" + LONG_VERSION + "\": {}}}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody("{}")));
        byte[] tarball = "ok".getBytes();
        when(proxyStreamClient.streamContent(any(String.class), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream(tarball)));

        ResponseEntity<byte[]> response = proxyRestClient.get()
                .uri("http://registry.npmjs.org/" + name + "/-/" + name + "-" + LONG_VERSION + ".tgz")
                .retrieve()
                .toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(tarball);

        List<Map<String, Object>> logs = awaitAuditLogRow(name);
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).get("package_version")).isEqualTo(LONG_VERSION);
        assertThat(logs.get(0).get("decision_source")).isEqualTo("OSV_LIVE");
        assertThat(logs.get(0).get("verdict")).isEqualTo("ALLOW");

        assertThat(jdbcClient.sql("SELECT package_version FROM package_metadata WHERE package_name = ?")
                .params(name).query(String.class).list()).containsExactly(LONG_VERSION);
        assertThat(jdbcClient.sql("SELECT package_version FROM api_cache WHERE package_name = ?")
                .params(name).query(String.class).list()).containsExactly(LONG_VERSION);

        apiCallLogDao.flushBuffer();
        assertThat(jdbcClient.sql("SELECT package_version FROM api_call_log WHERE package_name = ?")
                .params(name).query(String.class).list()).contains(LONG_VERSION);
    }

    @Test
    void shouldBlockAndAuditLongVersionMatchedByExactCompanyPolicy() throws Exception {
        String name = "long-version-blocked-pkg";
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
                VALUES (?, 'npm', ?, 'BLOCK', 'Exact long version banned', 'admin', NOW())
                """).params(name, LONG_VERSION).update();

        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/" + name + "/-/" + name + "-" + LONG_VERSION + ".tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should have thrown 403 Forbidden");
        } catch (HttpClientErrorException.Forbidden e) {
            assertThat(e.getResponseBodyAsString())
                    .contains("\"step\":\"COMPANY_POLICY\"")
                    .contains("\"version\":\"" + LONG_VERSION + "\"")
                    .contains("\"detail\":\"Exact long version banned\"");
        }

        List<Map<String, Object>> logs = awaitAuditLogRow(name);
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).get("package_version")).isEqualTo(LONG_VERSION);
        assertThat(logs.get(0).get("decision_source")).isEqualTo("COMPANY_POLICY");
        assertThat(logs.get(0).get("verdict")).isEqualTo("BLOCK");
    }

    // Wait for async (Loom) writing of an audit log row, up to 2.5s (50 x 50ms), as in
    // ProxyControllerIntegrationTest.
    private List<Map<String, Object>> awaitAuditLogRow(String packageName) throws InterruptedException {
        for (int attempts = 0; attempts < 50; attempts++) {
            List<Map<String, Object>> logs = jdbcClient.sql(
                    "SELECT * FROM proxy_audit_logs WHERE package_name = ?").params(packageName).query().listOfRows();
            if (!logs.isEmpty()) {
                return logs;
            }
            Thread.sleep(50);
        }
        return List.of();
    }
}
