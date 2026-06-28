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

import com.silicaproxy.dao.client.ProxyStreamClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests with real calls to public registries (npm, PyPI).
 * Validates the detection of deprecated/yanked packages via the full flow
 * ProxyController -> SecurityService -> RegistryClient -> public registry.
 *
 * Does not extend BaseIntegrationTest to avoid substituting registry URLs with WireMock.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DeprecationRealCallsIntegrationTest {

    private static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine");

    static {
        postgres.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("silicaproxy.security.ssrf-protection.enabled", () -> "false");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-path", () -> "");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-password", () -> "");
        registry.add("silicaproxy.proxy.port", () -> 0);
        // Quarantine disabled : old packages must not be blocked by age
        registry.add("silicaproxy.quarantine.enabled", () -> "false");
        // Deprecation enabled for npm and pypi
        registry.add("silicaproxy.deprecation.enabled", () -> "true");
        registry.add("silicaproxy.deprecation.ecosystems.npm", () -> "true");
        registry.add("silicaproxy.deprecation.ecosystems.pypi", () -> "true");
        // Fallback chain disabled : we want to test only the step REGISTRY_DEPRECATION
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;

    @BeforeEach
    void setUp() throws Exception {
        jdbcClient.sql("DELETE FROM company_policies").update();
        jdbcClient.sql("DELETE FROM public_vulnerabilities").update();
        jdbcClient.sql("DELETE FROM api_cache").update();
        jdbcClient.sql("DELETE FROM package_metadata").update();

        when(proxyStreamClient.streamContent(any(), any()))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK, new HttpHeaders(), new ByteArrayInputStream("ok".getBytes())));

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        this.proxyRestClient = RestClient.builder().requestFactory(factory).build();
    }

    // — npm ——————————————————————————————————————————————————————————————————

    @Test
    void shouldBlockDeprecatedNpmPackage_request() {
        // request@2.88.2 : deprecated since 2020, "deprecated" field present in npm metadata
        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/request/-/request-2.88.2.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should throw 403 for a deprecated npm package");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"step\":\"REGISTRY_DEPRECATION\"")
                    .contains("\"package\":\"request\"")
                    .contains("\"version\":\"2.88.2\"")
                    .contains("\"ecosystem\":\"npm\"");
        }
    }

    @Test
    void shouldBlockDeprecatedNpmPackage_csurf() {
        // csurf@1.11.0 : archived and no longer maintained, "deprecated" field present in npm metadata
        try {
            proxyRestClient.get()
                    .uri("http://registry.npmjs.org/csurf/-/csurf-1.11.0.tgz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should throw 403 for a deprecated npm package");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"step\":\"REGISTRY_DEPRECATION\"")
                    .contains("\"package\":\"csurf\"")
                    .contains("\"version\":\"1.11.0\"")
                    .contains("\"ecosystem\":\"npm\"");
        }
    }

    // — PyPI ——————————————————————————————————————————————————————————————————

    @Test
    void shouldBlockYankedPypiPackage_urllib3() {
        // urllib3@1.25 : yanked ("Broken release"), "yanked": true field in PyPI metadata
        try {
            proxyRestClient.get()
                    .uri("http://files.pythonhosted.org/packages/source/u/urllib3/urllib3-1.25.tar.gz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should throw 403 for a yanked PyPI package");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"step\":\"REGISTRY_DEPRECATION\"")
                    .contains("\"package\":\"urllib3\"")
                    .contains("\"version\":\"1.25\"")
                    .contains("\"ecosystem\":\"pypi\"");
        }
    }

    @Test
    void shouldBlockYankedPypiPackage_certifi() {
        // certifi@2022.5.18 : yanked ("Incorrectly claims to support Python 3.5.")
        try {
            proxyRestClient.get()
                    .uri("http://files.pythonhosted.org/packages/source/c/certifi/certifi-2022.5.18.tar.gz")
                    .retrieve()
                    .toBodilessEntity();
            fail("Should throw 403 for a yanked PyPI package");
        } catch (HttpClientErrorException.Forbidden e) {
            String body = e.getResponseBodyAsString();
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body)
                    .contains("\"step\":\"REGISTRY_DEPRECATION\"")
                    .contains("\"package\":\"certifi\"")
                    .contains("\"version\":\"2022.5.18\"")
                    .contains("\"ecosystem\":\"pypi\"");
        }
    }

}
