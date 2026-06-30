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


package com.silicaproxy.performance;

import com.silicaproxy.service.interception.LoomProxyServer;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "silicaproxy.registries.npm-url=https://registry.npmjs.org",
        "silicaproxy.registries.pypi-url=https://pypi.org",
        "silicaproxy.registries.maven-url=https://repo1.maven.org",
        "silicaproxy.security.ssrf-protection.enabled=false",
        "silicaproxy.osv-incremental.enabled=false",
        // Quarantine disabled for load testing: fake packages don't exist in real registries,
        // so the quarantine call fails open and caches an ALLOW that bypasses all other checks.
        "silicaproxy.quarantine.enabled=false"
})
@Testcontainers
@NullMarked
class ProxyK6LoadTest {

    @Container
    private static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:18-alpine")
            .withCommand("postgres",
                    "-c", "shared_buffers=512MB",
                    "-c", "work_mem=16MB",
                    "-c", "max_connections=1000",
                    "-c", "synchronous_commit=off",
                    "-c", "fsync=off");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("silicaproxy.proxy.port", () -> 0);
    }

    private final LoomProxyServer loomProxyServer;
    private final JdbcClient jdbcClient;
    private final JdbcTemplate jdbcTemplate;
    private final com.silicaproxy.service.decision.SecurityService securityService;

    @Autowired
    ProxyK6LoadTest(LoomProxyServer loomProxyServer, JdbcClient jdbcClient, JdbcTemplate jdbcTemplate,
            com.silicaproxy.service.decision.SecurityService securityService) {
        this.loomProxyServer = loomProxyServer;
        this.jdbcClient = jdbcClient;
        this.jdbcTemplate = jdbcTemplate;
        this.securityService = securityService;
    }

    @Test
    void runK6LoadTest() throws Exception {
        // 1. Clean up and populate database
        jdbcClient.sql("TRUNCATE company_policies, public_vulnerabilities, api_cache, package_metadata RESTART IDENTITY CASCADE").update();

        List<Object[]> policies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            policies.add(new Object[]{"blocked-company-" + i, "npm", "*", "BLACKLIST", "Blocked by company governance policy", "admin-test"});
        }
        for (int i = 0; i < 10000; i++) {
            policies.add(new Object[]{"blocked-pypi-" + i, "pypi", "*", "BLACKLIST", "Blocked by company governance policy", "admin-test"});
        }
        for (int i = 0; i < 10000; i++) {
            policies.add(new Object[]{"com.example:blocked-maven-" + i, "maven", "*", "BLACKLIST", "Blocked by company governance policy", "admin-test"});
        }
        policies.add(new Object[]{"ansi-styles", "npm", "5.2.0", "WHITELIST", "Allowed for testing streaming performance", "admin-test"});

        jdbcTemplate.batchUpdate("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """, policies);

        List<Object[]> vulns = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            vulns.add(new Object[]{"GHSA-2026-" + i, "GITHUB", "blocked-vuln-" + i, "npm", "Test vulnerability summary " + i, "Test vulnerability details " + i, "[\"1.0.0\"]", 9.5});
        }
        for (int i = 0; i < 10000; i++) {
            vulns.add(new Object[]{"MAL-2026-" + i, "OPENSSF", "malicious-pkg-" + i, "npm", "Malicious package " + i, "Malicious package details " + i, "[\"1.0.0\"]", 0.0});
        }
        for (int i = 0; i < 10000; i++) {
            vulns.add(new Object[]{"GHSA-PYPI-" + i, "GITHUB", "blocked-pypi-vuln-" + i, "pypi", "Test PyPI vulnerability summary " + i, "Test PyPI vulnerability details " + i, "[\"1.0.0\"]", 9.5});
        }
        for (int i = 0; i < 10000; i++) {
            vulns.add(new Object[]{"GHSA-MAVEN-" + i, "GITHUB", "com.example:blocked-maven-vuln-" + i, "maven", "Test Maven vulnerability summary " + i, "Test Maven vulnerability details " + i, "[\"1.0.0\"]", 9.5});
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score)
                VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?)
                """, vulns);

        // 2. Resolve the proxy TCP port
        int proxyPort = loomProxyServer.getProxyPort();
        String proxyUrl = "http://host.testcontainers.internal:" + proxyPort;

        org.testcontainers.Testcontainers.exposeHostPorts(proxyPort);

        // 3. Start k6 container (writing in /tmp/ to avoid permission issues)
        try (GenericContainer<?> k6 = new GenericContainer<>(DockerImageName.parse("grafana/k6:0.51.0"))
                .withCopyFileToContainer(
                        MountableFile.forClasspathResource("k6-script.js"),
                        "/k6-script.js"
                )
                .withCommand("run", "--summary-export=/tmp/k6-report.json", "/k6-script.js")
                .withEnv("HTTP_PROXY", proxyUrl)
                .withEnv("http_proxy", proxyUrl)
                .withEnv("HTTPS_PROXY", proxyUrl)
                .withEnv("https_proxy", proxyUrl)
                .withAccessToHost(true)) {

            k6.start();

            // Wait for execution to complete
            while (k6.isRunning()) {
                Thread.sleep(250);
            }

            // 4. Extraction et affichage des logs de la console
            String logs = k6.getLogs();
            System.out.println("==================================================================");
            System.out.println("                      K6 PERFORMANCE RESULTS                      ");
            System.out.println("==================================================================");
            System.out.println(logs);
            System.out.println("==================================================================");

            // 5. Absolute resolution of Gradle build directory
            String userDir = System.getProperty("user.dir");
            Path buildDir = Paths.get(userDir, "build");
            
            if (!Files.exists(buildDir) && Files.exists(Paths.get(userDir, "..", "build"))) {
                buildDir = Paths.get(userDir, "..", "build");
            }

            Files.createDirectories(buildDir); 

            // Write console logs (always available, even if k6 crashes)
            File logFile = buildDir.resolve("k6-output.log").toFile();
            Files.writeString(logFile.toPath(), logs);
            System.out.println("INFO: k6 log file written to: " + logFile.getAbsolutePath());

            // Attempt to copy the JSON report safely
            try {
                File jsonFile = buildDir.resolve("k6-report.json").toFile();
                k6.copyFileFromContainer("/tmp/k6-report.json", jsonFile.getAbsolutePath());
                System.out.println("INFO: k6 JSON report copied to: " + jsonFile.getAbsolutePath());
            } catch (Exception e) {
                System.err.println("WARNING: Could not export JSON summary (it may not have been generated): " + e.getMessage());
            }

            // Assert that K6 ran and exited with 0
            Long exitCode = k6.getCurrentContainerInfo().getState().getExitCodeLong();
            assertThat(exitCode).isEqualTo(0L);
        }
    }
}