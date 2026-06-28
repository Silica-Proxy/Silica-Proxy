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


package com.silicaproxy;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@NullMarked
public abstract class BaseIntegrationTest {

    protected static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine")
        .withCommand("postgres",
                     "-c", "shared_buffers=512MB",
                     "-c", "work_mem=16MB",
                     "-c", "max_connections=1000",
                     "-c", "synchronous_commit=off",
                     "-c", "fsync=off");

    protected static final WireMockServer wireMock = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());

    static {
        postgres.start();
        wireMock.start();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // DB Properties
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);

        // WireMock Mocking URLs
        String wiremockUrl = "http://localhost:" + wireMock.port();
        registry.add("silicaproxy.registries.npm-url", () -> wiremockUrl);
        registry.add("silicaproxy.registries.pypi-url", () -> wiremockUrl);
        registry.add("silicaproxy.registries.maven-url", () -> wiremockUrl);
        registry.add("silicaproxy.api-fallback.osv.url", () -> wiremockUrl + "/v1/query");
        registry.add("silicaproxy.security.ssrf-protection.enabled", () -> "false");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-path", () -> "");
        registry.add("silicaproxy.ssl-mitm.ca-keystore-password", () -> "");
        registry.add("silicaproxy.proxy.port", () -> 0);

        // Reduced outgoing HTTP timeouts so that tests simulating a frozen remote server
        // (WireMock withFixedDelay beyond this threshold) end quickly.
        registry.add("silicaproxy.http-client.connect-timeout-seconds", () -> 2);
        registry.add("silicaproxy.http-client.registries-read-timeout-seconds", () -> 2);
        registry.add("silicaproxy.http-client.security-apis-read-timeout-seconds", () -> 2);
    }

    // Load a sample of real data (extract from a real ArtifactSentry instance
    // synchronized with OSV) from src/test/resources/fixtures/, for more representative tests
    // than fully synthetic data. Executed in a single JDBC Statement (pgjdbc natively supports
    // multiple ';' separated instructions), so no manual fragile SQL splitting.
    protected static void loadSqlFixture(JdbcTemplate jdbcTemplate, String classpathLocation) {
        try (InputStream is = BaseIntegrationTest.class.getClassLoader().getResourceAsStream(classpathLocation)) {
            if (is == null) {
                throw new IllegalStateException("Fixture introuvable : " + classpathLocation);
            }
            String sql = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            jdbcTemplate.execute(sql);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
