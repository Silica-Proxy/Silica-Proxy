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


package com.silicaproxy.controller.realtoolchain;

import com.silicaproxy.service.interception.LoomProxyServer;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;
import java.util.UUID;

/**
 * Base class for real-toolchain integration tests. Sets up shared infrastructure:
 * PostgreSQL, Testcontainers networking, npm/pip/Gradle CLIs, and security policy helpers.
 * Subclasses focus only on their specific ecosystem's test scenarios.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
abstract class BaseRealToolchainTest {

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
        registry.add("silicaproxy.quarantine.enabled", () -> "false");
        registry.add("silicaproxy.deprecation.enabled", () -> "false");
        // Enabled (with the ecosystem thresholds from application-test.yaml: maven/pypi 7.0,
        // npm 9.0) so real-toolchain tests can inject a public_vulnerabilities row and verify
        // the CVSS block reaches the real CLI as a 403. Safe for the other tests in this
        // package: the table is empty unless a test explicitly inserts into it.
        registry.add("silicaproxy.severity-threshold.enabled", () -> "true");
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
    }

    @LocalServerPort
    protected int port;

    @Autowired
    protected LoomProxyServer loomProxyServer;

    @Autowired
    protected JdbcClient jdbcClient;

    protected static boolean toolchainStarted = false;
    protected static GenericContainer<?> npmContainer;
    protected static GenericContainer<?> pipContainer;

    @BeforeEach
    void setUp() {
        jdbcClient.sql("DELETE FROM company_policies").update();
        jdbcClient.sql("DELETE FROM public_vulnerabilities WHERE source = 'TEST'").update();

        if (!toolchainStarted) {
            int loomPort = loomProxyServer.getProxyPort();
            Testcontainers.exposeHostPorts(port, loomPort);

            npmContainer = new GenericContainer<>(DockerImageName.parse("node:24-alpine"))
                    .withCommand("tail", "-f", "/dev/null");
            npmContainer.start();

            pipContainer = new GenericContainer<>(DockerImageName.parse("python:3.14-slim"))
                    .withCommand("tail", "-f", "/dev/null");
            pipContainer.start();

            toolchainStarted = true;
        }
    }

    protected void blacklist(String packageName, String ecosystem) {
        blacklist(packageName, ecosystem, "%");
    }

    protected void blacklist(String packageName, String ecosystem, String versionPattern) {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by, updated_at)
                VALUES (:packageName, :ecosystem, :versionPattern, 'BLACKLIST', 'Blocked for real-toolchain BLOCK test', 'test', NOW())
                """)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("versionPattern", versionPattern)
                .update();
    }

    protected void injectVulnerability(String packageName, String ecosystem, String version, double cvssScore) {
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities
                    (id, source, package_name, ecosystem, summary, affected_versions, cvss_score, published_at)
                VALUES (:id, 'TEST', :packageName, :ecosystem, 'Injected for real-toolchain BLOCK test',
                        CAST(:affectedVersions AS JSONB), :cvssScore, NOW())
                """)
                .param("id", "TEST-" + UUID.randomUUID())
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("affectedVersions", "[\"" + version + "\"]")
                .param("cvssScore", cvssScore)
                .update();
    }

    protected void assertDecisionCached(String packageName, String version, String ecosystem, String expectedResult) {
        var decision = jdbcClient.sql("""
                SELECT package_name, ecosystem, package_version, is_secure, api_source
                FROM api_cache
                WHERE package_name = :packageName AND ecosystem = :ecosystem AND package_version = :version
                """)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("version", version)
                .query((rs, rowNum) -> Map.of(
                    "package", rs.getString("package_name"),
                    "ecosystem", rs.getString("ecosystem"),
                    "version", rs.getString("package_version"),
                    "result", rs.getBoolean("is_secure") ? "ALLOW" : "BLOCK",
                    "source", rs.getString("api_source")
                ))
                .optional();

        if (decision.isPresent()) {
            var d = decision.get();
            System.out.printf("Decision cached: ecosystem=%s, package=%s, version=%s → %s (source=%s)%n",
                    d.get("ecosystem"), d.get("package"), d.get("version"), d.get("result"), d.get("source"));
        }
    }
}
