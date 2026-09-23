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
import com.silicaproxy.config.Metrics;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The quarantine publish date of an npm package comes from the public registry first ; the
 * relayed packument / origin registry is only a fallback when the public registry does NOT know
 * the version (404), never when it merely failed to answer.
 */
@TestPropertySource(properties = {
    "silicaproxy.api-fallback.osv.enabled=false",
    "silicaproxy.api-fallback.deps-dev.enabled=false"
})
class SecurityServiceNpmPublicFirstTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final NpmPackumentIndex npmPackumentIndex;
    private final JdbcClient jdbcClient;
    private final MeterRegistry meterRegistry;

    @Autowired
    SecurityServiceNpmPublicFirstTest(SecurityService securityService, NpmPackumentIndex npmPackumentIndex,
            JdbcClient jdbcClient, MeterRegistry meterRegistry) {
        this.securityService = securityService;
        this.npmPackumentIndex = npmPackumentIndex;
        this.jdbcClient = jdbcClient;
        this.meterRegistry = meterRegistry;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();
    }

    private static String packument(String name, String version, String time) {
        return "{\"name\":\"" + name + "\","
                + "\"time\":{\"" + version + "\":\"" + time + "\"},"
                + "\"versions\":{\"" + version + "\":{\"name\":\"" + name + "\",\"version\":\"" + version + "\","
                + "\"dist\":{\"tarball\":\"https://mirror.example/" + name + "-" + version + ".tgz\"}}}}";
    }

    // A packument relayed from another registry, claiming an OLD publish date for the version.
    private void indexOldDateFromOtherRegistry(String name, String version) {
        String oldDate = Instant.now().minus(400, ChronoUnit.DAYS).toString();
        npmPackumentIndex.indexPackument(packument(name, version, oldDate).getBytes(StandardCharsets.UTF_8),
                null, "https://mirror.example/" + name);
    }

    private double count(String metric, String tagKey, String tagValue) {
        Counter counter = meterRegistry.find(metric)
                .tag(Metrics.TAG_ECOSYSTEM, "npm")
                .tag(tagKey, tagValue)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    @Test
    void shouldPreferPublicRegistryDateOverRelayedPackumentDate() {
        indexOldDateFromOtherRegistry("poisoned-date-pkg", "1.0.0");
        String youngDate = Instant.now().minus(1, ChronoUnit.DAYS).toString();
        wireMock.stubFor(get(urlEqualTo("/poisoned-date-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(packument("poisoned-date-pkg", "1.0.0", youngDate))));
        double before = count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_PUBLIC_REGISTRY);

        DecisionResult decision = securityService.getDecision("poisoned-date-pkg", "1.0.0", "npm", "");

        // The relayed packument's "400 days old" claim does not let a 1-day-old version through.
        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_QUARANTINE");
        assertThat(count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_PUBLIC_REGISTRY))
                .isEqualTo(before + 1);
    }

    @Test
    void shouldFallBackToRelayedPackumentDateWhenPublicRegistryReturns404() {
        indexOldDateFromOtherRegistry("private-only-pkg", "2.0.0");
        wireMock.stubFor(get(urlEqualTo("/private-only-pkg")).willReturn(aResponse().withStatus(404)));
        double before = count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_ORIGIN_REGISTRY);

        DecisionResult decision = securityService.getDecision("private-only-pkg", "2.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        wireMock.verify(1, getRequestedFor(urlEqualTo("/private-only-pkg")));
        assertThat(count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_ORIGIN_REGISTRY))
                .isEqualTo(before + 1);
    }

    @Test
    void shouldNotFallBackToRelayedPackumentWhenPublicRegistryIsDown() {
        indexOldDateFromOtherRegistry("outage-pkg", "3.0.0");
        wireMock.stubFor(get(urlEqualTo("/outage-pkg")).willReturn(aResponse().withStatus(503)));
        double unresolvedBefore = count(Metrics.PUBLISH_DATE_UNRESOLVED_METRIC, Metrics.TAG_VERDICT, "ALLOW");
        double lookupBefore = count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_UNRESOLVED);

        DecisionResult decision = securityService.getDecision("outage-pkg", "3.0.0", "npm", "");

        // The relayed date is ignored : fail-open policy (default true) decides, and it is counted.
        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(count(Metrics.PUBLISH_DATE_UNRESOLVED_METRIC, Metrics.TAG_VERDICT, "ALLOW"))
                .isEqualTo(unresolvedBefore + 1);
        assertThat(count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_UNRESOLVED))
                .isEqualTo(lookupBefore + 1);
    }

    @Test
    void shouldUseLocallyCachedDateWhenPublicRegistryIsDown() {
        Instant oldDate = Instant.now().minus(100, ChronoUnit.DAYS);
        jdbcClient.sql("INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at) "
                        + "VALUES ('cached-outage-pkg', 'npm', '1.0.0', :publishedAt)")
                .param("publishedAt", java.sql.Timestamp.from(oldDate))
                .update();
        wireMock.stubFor(get(urlEqualTo("/cached-outage-pkg")).willReturn(aResponse().withStatus(500)));
        double before = count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_LOCAL_CACHE);

        DecisionResult decision = securityService.getDecision("cached-outage-pkg", "1.0.0", "npm", "");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
        assertThat(count(Metrics.PUBLISH_DATE_LOOKUPS_METRIC, Metrics.TAG_SOURCE, Metrics.DATE_SOURCE_LOCAL_CACHE))
                .isEqualTo(before + 1);
    }
}
