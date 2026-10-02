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


package com.silicaproxy.dao.policy;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.DecisionResult;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** A cached BLOCK verdict must say why the package is blocked, not just "Validated via API cache". */
class ApiCacheBlockReasonTest extends BaseIntegrationTest {

    private static final String PKG = "com.acme:cache-reason-lib";

    private final MetadataCacheDao metadataCacheDao;
    private final DecisionDao decisionDao;
    private final JdbcClient jdbcClient;

    @Autowired
    ApiCacheBlockReasonTest(MetadataCacheDao metadataCacheDao, DecisionDao decisionDao, JdbcClient jdbcClient) {
        this.metadataCacheDao = metadataCacheDao;
        this.decisionDao = decisionDao;
        this.jdbcClient = jdbcClient;
    }

    private static Instant tomorrow() {
        return Instant.now().plus(1, ChronoUnit.DAYS);
    }

    private DecisionResult decisionFor(String version) {
        return decisionDao.evaluateDecision(PKG, version, "maven", 7.0).orElseThrow();
    }

    @Test
    void cachedBlockReasonListsTheVulnerabilityIdsAndTheSource() {
        metadataCacheDao.saveApiCache(PKG, "maven", "1.0.0", false, "OSV_LIVE", tomorrow(),
                List.of("GHSA-cxp5-3px4-pw24", "CVE-2026-0001"));

        DecisionResult decision = decisionFor("1.0.0");

        assertThat(decision.sourceType()).isEqualTo("API_CACHE");
        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.reason())
                .startsWith("Blocked by cached OSV_LIVE verdict: ")
                .contains("GHSA-cxp5-3px4-pw24")
                .contains("CVE-2026-0001");
    }

    @Test
    void cachedBlockWithoutIdsStillNamesTheSource() {
        metadataCacheDao.saveApiCache(PKG, "maven", "2.0.0", false, "REGISTRY_DEPRECATION", tomorrow());

        assertThat(decisionFor("2.0.0").reason()).isEqualTo("Blocked by cached REGISTRY_DEPRECATION verdict");
    }

    @Test
    void cachedAllowKeepsItsReason() {
        metadataCacheDao.saveApiCache(PKG, "maven", "3.0.0", true, "OSV_LIVE", tomorrow(), List.of());

        DecisionResult decision = decisionFor("3.0.0");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.reason()).isEqualTo("Validated via API cache");
    }

    @Test
    void resavingAVerdictReplacesThePreviousIds() {
        metadataCacheDao.saveApiCache(PKG, "maven", "4.0.0", false, "OSV_LIVE", tomorrow(), List.of("GHSA-old"));
        metadataCacheDao.saveApiCache(PKG, "maven", "4.0.0", false, "DEPS_DEV", tomorrow(), List.of("GHSA-new"));

        assertThat(decisionFor("4.0.0").reason())
                .isEqualTo("Blocked by cached DEPS_DEV verdict: GHSA-new");

        metadataCacheDao.saveApiCache(PKG, "maven", "4.0.0", false, "DEPS_DEV", tomorrow());

        assertThat(decisionFor("4.0.0").reason()).isEqualTo("Blocked by cached DEPS_DEV verdict");
    }

    @Test
    void idsWithQuotesAreStoredAsDataNotAsSql() {
        String hostile = "GHSA-\"x'; DROP TABLE api_cache; --";
        metadataCacheDao.saveApiCache(PKG, "maven", "5.0.0", false, "OSV_LIVE", tomorrow(), List.of(hostile));

        assertThat(decisionFor("5.0.0").reason()).endsWith(hostile);
        assertThat(jdbcClient.sql("SELECT count(*) FROM api_cache WHERE package_name = :p")
                .param("p", PKG).query(Long.class).single()).isGreaterThanOrEqualTo(1L);
    }
}
