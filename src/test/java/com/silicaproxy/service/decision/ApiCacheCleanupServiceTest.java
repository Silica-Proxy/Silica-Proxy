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


package com.silicaproxy.service.decision;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.MetadataCacheDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ApiCacheCleanupServiceTest extends BaseIntegrationTest {

    @Autowired
    private MetadataCacheDao metadataCacheDao;

    @Autowired
    private JdbcClient jdbcClient;

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // No specific properties needed for cache cleanup
    }

    @BeforeEach
    void setup() {
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE shedlock RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldCleanExpiredApiCache() {
        // Insert expired and valid cache entries - use fixed past date to ensure expiration
        jdbcClient.sql("INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at) VALUES (?, ?, ?, ?, ?, ?)").params(
                "expired-pkg", "npm", "1.0", true, "osv", Timestamp.from(Instant.parse("2020-01-01T00:00:00Z"))).update();
        jdbcClient.sql("INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at) VALUES (?, ?, ?, ?, ?, ?)").params(
                "valid-pkg", "npm", "1.0", true, "osv", Timestamp.from(Instant.now().plus(1, ChronoUnit.DAYS))).update();

        // Call DAO directly to avoid @SchedulerLock conflicts with scheduled tasks
        int deleted = metadataCacheDao.deleteExpiredApiCache();

        List<Map<String, Object>> cache = jdbcClient.sql("SELECT package_name FROM api_cache").query().listOfRows();
        assertThat(cache).hasSize(1);
        assertThat(cache.get(0).get("package_name")).isEqualTo("valid-pkg");
        assertThat(deleted).isEqualTo(1);
    }

    @Test
    void shouldNotDeleteNonExpiredEntries() {
        // Insert only valid cache entries
        jdbcClient.sql("INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at) VALUES (?, ?, ?, ?, ?, ?)").params(
                "valid-pkg-1", "npm", "1.0", true, "osv", Timestamp.from(Instant.now().plus(1, ChronoUnit.DAYS))).update();
        jdbcClient.sql("INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at) VALUES (?, ?, ?, ?, ?, ?)").params(
                "valid-pkg-2", "maven", "2.0", false, "sonatype", Timestamp.from(Instant.now().plus(2, ChronoUnit.DAYS))).update();

        // Call DAO directly to avoid @SchedulerLock conflicts with scheduled tasks
        int deleted = metadataCacheDao.deleteExpiredApiCache();

        List<Map<String, Object>> cache = jdbcClient.sql("SELECT package_name FROM api_cache ORDER BY package_name").query().listOfRows();
        assertThat(cache).hasSize(2);
        assertThat(cache.get(0).get("package_name")).isEqualTo("valid-pkg-1");
        assertThat(cache.get(1).get("package_name")).isEqualTo("valid-pkg-2");
        assertThat(deleted).isEqualTo(0);
    }

    @Test
    void shouldDeleteAllExpiredEntries() {
        // Insert only expired cache entries - use fixed past dates to ensure expiration
        jdbcClient.sql("INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at) VALUES (?, ?, ?, ?, ?, ?)").params(
                "expired-pkg-1", "npm", "1.0", true, "osv", Timestamp.from(Instant.parse("2020-01-01T00:00:00Z"))).update();
        jdbcClient.sql("INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at) VALUES (?, ?, ?, ?, ?, ?)").params(
                "expired-pkg-2", "maven", "2.0", false, "sonatype", Timestamp.from(Instant.parse("2019-01-01T00:00:00Z"))).update();

        // Call DAO directly to avoid @SchedulerLock conflicts with scheduled tasks
        int deleted = metadataCacheDao.deleteExpiredApiCache();

        List<Map<String, Object>> cache = jdbcClient.sql("SELECT package_name FROM api_cache").query().listOfRows();
        assertThat(cache).isEmpty();
        assertThat(deleted).isEqualTo(2);
    }
}
