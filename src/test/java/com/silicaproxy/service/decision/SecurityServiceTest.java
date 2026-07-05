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

import com.silicaproxy.config.Metrics;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.policy.MetadataCacheDao;
import com.silicaproxy.model.dto.DecisionResult;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

@TestPropertySource(properties = "silicaproxy.quarantine.ecosystems.npm.enabled=true")
class SecurityServiceTest extends BaseIntegrationTest {

    private final SecurityService securityService;
    private final SeverityMappingsCache severityMappingsCache;
    private final JdbcClient jdbcClient;
    private final MetadataCacheDao metadataCacheDao;
    private final MeterRegistry meterRegistry;

    @Autowired
    SecurityServiceTest(
            SecurityService securityService,
            SeverityMappingsCache severityMappingsCache,
            JdbcClient jdbcClient,
            MetadataCacheDao metadataCacheDao,
            MeterRegistry meterRegistry) {
        this.securityService = securityService;
        this.severityMappingsCache = severityMappingsCache;
        this.jdbcClient = jdbcClient;
        this.metadataCacheDao = metadataCacheDao;
        this.meterRegistry = meterRegistry;
    }

    // The MeterRegistry bean is shared across every test in this class (and reused across the
    // whole Spring test context), so counters persist between tests -- reading a before/after
    // delta around the call under test is the only way to assert "this call incremented it by
    // exactly one" without depending on test execution order.
    private double apiCallCount(String source, String result) {
        io.micrometer.core.instrument.Counter counter = meterRegistry
                .find(Metrics.EXTERNAL_API_CALLS_METRIC)
                .tag(Metrics.TAG_SOURCE, source)
                .tag(Metrics.TAG_RESULT, result)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    private double localEvaluationCount(String outcome) {
        io.micrometer.core.instrument.Counter counter = meterRegistry
                .find(Metrics.LOCAL_EVALUATION_METRIC)
                .tag(Metrics.TAG_OUTCOME, outcome)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    @BeforeEach
    void cleanDbAndWiremock() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        // severity_mappings isn't truncated (it's reference data, not per-test fixtures), but
        // shouldPickUpSeverityMappingChangesAfterRefresh mutates it directly -- reset it (DB and
        // the in-memory cache, which TRUNCATE alone wouldn't touch) so that test's changes never
        // bleed into others regardless of execution order.
        jdbcClient.sql("UPDATE severity_mappings SET min_cvss = 7.0, max_cvss = 8.9 WHERE severity_level = 'HIGH'").update();
        severityMappingsCache.refresh();
        wireMock.resetAll();
    }

    @Test
    void shouldAllowWhenPolicyWhitelists() {
        jdbcClient.sql("""
            INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
            VALUES ('whitelisted-pkg', 'npm', '*', 'WHITELIST', 'Allowed package', 'security')
            """).update();

        double before = localEvaluationCount(Metrics.OUTCOME_HIT);
        DecisionResult decision = securityService.getDecision("whitelisted-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("WHITELIST");
        assertThat(decision.sourceType()).isEqualTo("COMPANY_POLICY");
        assertThat(localEvaluationCount(Metrics.OUTCOME_HIT) - before).isEqualTo(1.0);
    }

    @Test
    void shouldBlockWhenVulnerabilityExists() {
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
            VALUES ('CVE-123', 'OSV', 'vuln-pkg', 'npm', 'Critical bug', '["1.0.0"]'::jsonb, 9.8)
            """).update();

        double before = localEvaluationCount(Metrics.OUTCOME_HIT);
        DecisionResult decision = securityService.getDecision("vuln-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("PUBLIC_VULN");
        assertThat(localEvaluationCount(Metrics.OUTCOME_HIT) - before).isEqualTo(1.0);
    }

    @Test
    void shouldPickUpSeverityMappingChangesAfterRefresh() {
        // maven's configured floor is min(7.0 configured, severityMappings["HIGH"].minCvss());
        // HIGH.min_cvss defaults to 7.0 (V1 migration), so a CVSS 6.0 vulnerability isn't blocked
        // yet -- the package falls through to registry resolution instead (no WireMock stub for
        // it here, so it ends up as a REGISTRY_ERROR fail-open ALLOW).
        jdbcClient.sql("""
            INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
            VALUES ('GHSA-refresh-test', 'OSV', 'refresh-pkg', 'maven', 'Moderate issue', '["1.0.0"]'::jsonb, 6.0)
            """).update();

        DecisionResult beforeRefresh = securityService.getDecision("refresh-pkg", "1.0.0", "maven");
        assertThat(beforeRefresh.sourceType()).isNotEqualTo("PUBLIC_VULN");

        // Lower HIGH's floor below 6.0 directly in the DB (as an administrator would), then
        // refresh the in-memory cache without restarting the instance.
        jdbcClient.sql("UPDATE severity_mappings SET min_cvss = 5.0 WHERE severity_level = 'HIGH'").update();
        severityMappingsCache.refresh();

        DecisionResult afterRefresh = securityService.getDecision("refresh-pkg", "1.0.0", "maven");
        assertThat(afterRefresh.result()).isEqualTo("BLOCK");
        assertThat(afterRefresh.sourceType()).isEqualTo("PUBLIC_VULN");
    }

    @Test
    void shouldBlockWhenQuarantined() {
        Instant publishedAt = Instant.now().minus(2, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/quarantine-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"quarantine-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        DecisionResult decision = securityService.getDecision("quarantine-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_QUARANTINE");
        assertThat(decision.reason()).contains("quarantine");

        Optional<Instant> dbPublishedAt = metadataCacheDao.getPackagePublishedAt("quarantine-pkg", "npm", "1.0.0");
        assertThat(dbPublishedAt).isPresent();
    }

    @Test
    void shouldBlockWhenDeprecated() {
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/deprecated-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {" +
                                "    \"1.0.0\": {" +
                                "      \"name\": \"deprecated-pkg\"," +
                                "      \"version\": \"1.0.0\"," +
                                "      \"deprecated\": \"Deprecated warning\"" +
                                "    }" +
                                "  }" +
                                "}")));

        DecisionResult decision = securityService.getDecision("deprecated-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_DEPRECATION");

        Map<String, Object> cache = jdbcClient.sql(
                "SELECT * FROM api_cache WHERE package_name = 'deprecated-pkg'").query().singleRow();
        assertThat(cache.get("is_secure")).isEqualTo(false);
        assertThat(cache.get("api_source")).isEqualTo("REGISTRY_DEPRECATION");
        assertThat(((Timestamp) cache.get("expires_at")).toInstant()).isAfter(Instant.now().plus(365, ChronoUnit.DAYS));
    }

    @Test
    void shouldBlockWhenDeprecatedEvenWhenPublishedAtAlreadyCached() {
        // Regression: package_metadata only ever persists published_at, never deprecation
        // status (by design -- deprecation must stay fresh, see SecurityService comment at
        // step 3). Pre-populating published_at here simulates a package/version already
        // resolved by an earlier, unrelated request (e.g. a prior quarantine check), and
        // verifies that this does NOT skip the live deprecation check on this request.
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES ('precached-deprecated-pkg', 'npm', '1.0.0', ?)
                """).params(Timestamp.from(publishedAt)).update();

        wireMock.stubFor(get(urlEqualTo("/precached-deprecated-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {" +
                                "    \"1.0.0\": {" +
                                "      \"name\": \"precached-deprecated-pkg\"," +
                                "      \"version\": \"1.0.0\"," +
                                "      \"deprecated\": \"Deprecated warning\"" +
                                "    }" +
                                "  }" +
                                "}")));

        DecisionResult decision = securityService.getDecision("precached-deprecated-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_DEPRECATION");
        wireMock.verify(1, getRequestedFor(urlEqualTo("/precached-deprecated-pkg")));
    }

    @Test
    void shouldFallBackToCachedPublishedAtWhenRegistryFailsButAlreadyKnown() {
        // If the registry is transiently down but this package/version was already resolved
        // before, quarantine must keep working off the cached publish date instead of failing
        // the whole request -- deprecation is simply left unknown (not deprecated) this round.
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES ('registry-down-known-pkg', 'npm', '1.0.0', ?)
                """).params(Timestamp.from(publishedAt)).update();

        wireMock.stubFor(get(urlEqualTo("/registry-down-known-pkg"))
                .willReturn(aResponse().withStatus(500)));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("registry-down-known-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldCallFallbackOsvAndCacheWhenSafe() {
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/safe-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"safe-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        double before = apiCallCount(Metrics.OSV_LIVE, "ALLOW");
        double missBefore = localEvaluationCount(Metrics.OUTCOME_MISS);
        DecisionResult decision = securityService.getDecision("safe-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(apiCallCount(Metrics.OSV_LIVE, "ALLOW") - before).isEqualTo(1.0);
        // Nothing in company_policies/public_vulnerabilities/api_cache for this package,
        // so the local SQL evaluation missed and OSV_LIVE had to be called (asserted above).
        assertThat(localEvaluationCount(Metrics.OUTCOME_MISS) - missBefore).isEqualTo(1.0);

        Map<String, Object> cache = jdbcClient.sql(
                "SELECT * FROM api_cache WHERE package_name = 'safe-pkg'").query().singleRow();
        assertThat(cache.get("is_secure")).isEqualTo(true);
        assertThat(cache.get("api_source")).isEqualTo("OSV_LIVE");
        Instant expiresAt = ((Timestamp) cache.get("expires_at")).toInstant();
        assertThat(expiresAt).isBefore(Instant.now().plus(25, ChronoUnit.HOURS));
        assertThat(expiresAt).isAfter(Instant.now().plus(23, ChronoUnit.HOURS));
    }

    @Test
    void shouldBlockWhenOsvDetectsVulnerability() {
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/vuln-osv-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"vuln-osv-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        // Mock of a vulnerability found by OSV
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                            {
                              "vulns": [
                                {
                                  "id": "GHSA-xxxx-yyyy",
                                  "summary": "Malicious package"
                                }
                              ]
                            }
                            """)));

        double before = apiCallCount(Metrics.OSV_LIVE, "BLOCK");
        DecisionResult decision = securityService.getDecision("vuln-osv-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("OSV_LIVE");
        assertThat(decision.reason()).contains("vulnerability");
        assertThat(apiCallCount(Metrics.OSV_LIVE, "BLOCK") - before).isEqualTo(1.0);
    }

    @Test
    void shouldAllowWhenOsvFails() {
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);

        wireMock.stubFor(get(urlEqualTo("/osv-fail-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {\"1.0.0\": {\"name\": \"osv-fail-pkg\", \"version\": \"1.0.0\"}}" +
                                "}")));

        // The fallback OSV API is down
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withStatus(500)));

        double before = apiCallCount(Metrics.OSV_LIVE, "ERROR");
        DecisionResult decision = securityService.getDecision("osv-fail-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW"); // Fail-open pour l'API de secours
        assertThat(decision.sourceType()).isEqualTo("OSV_LIVE");
        assertThat(apiCallCount(Metrics.OSV_LIVE, "ERROR") - before).isEqualTo(1.0);
    }

    @Test
    void shouldAllowWhenRegistryFailsAndFailOpen() {
        // The remote registry returns HTTP 500 error
        wireMock.stubFor(get(urlEqualTo("/down-pkg"))
                .willReturn(aResponse()
                        .withStatus(500)));

        DecisionResult decision = securityService.getDecision("down-pkg", "1.0.0", "npm");

        // Fail-open enabled by default in application.yaml
        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
        assertThat(decision.reason()).contains("Fail open due to public registry unavailability.");
    }

    @Test
    void shouldAllowWhenRegistryReturns404() {
        wireMock.stubFor(get(urlEqualTo("/not-found-pkg"))
                .willReturn(aResponse().withStatus(404)));

        DecisionResult decision = securityService.getDecision("not-found-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldAllowWhenPackageAgeEqualsQuarantineThreshold() {
        // PyPI: min-age-days = 10; age == threshold -> ageInDays >= minAgeDays -> no quarantine
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/pypi/boundary-pkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"info\": {\"version\": \"1.0.0\", \"yanked\": false}," +
                                "  \"releases\": {\"1.0.0\": [{\"upload_time\": \"" + publishedAt + "\"}]}" +
                                "}")));
        wireMock.stubFor(post(urlEqualTo("/v1/query"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        DecisionResult decision = securityService.getDecision("boundary-pkg", "1.0.0", "pypi");

        assertThat(decision.sourceType()).isNotEqualTo("REGISTRY_QUARANTINE");
        assertThat(decision.result()).isEqualTo("ALLOW");
    }

    @Test
    void shouldBlockWhenPackageAgeIsBelowQuarantineThreshold() {
        // PyPI: min-age-days = 10; age = 9 < 10 -> quarantine
        Instant publishedAt = Instant.now().minus(9, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/pypi/young-pypi-pkg/json"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"info\": {\"version\": \"1.0.0\", \"yanked\": false}," +
                                "  \"releases\": {\"1.0.0\": [{\"upload_time\": \"" + publishedAt + "\"}]}" +
                                "}")));

        DecisionResult decision = securityService.getDecision("young-pypi-pkg", "1.0.0", "pypi");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_QUARANTINE");
    }

    @Test
    void shouldBlockOnDeprecationEvenWhenPackageIsYoungEnoughForQuarantine() {
        // Deprecation is checked before quarantine in SecurityService.
        // A package that is both deprecated and recent (< threshold) must be blocked for REGISTRY_DEPRECATION,
        // not REGISTRY_QUARANTINE. The interaction between these two conditions is never exercised elsewhere.
        Instant publishedAt = Instant.now().minus(2, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/deprecated-and-young-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {" +
                                "    \"1.0.0\": {" +
                                "      \"name\": \"deprecated-and-young-pkg\"," +
                                "      \"version\": \"1.0.0\"," +
                                "      \"deprecated\": \"Malicious package removed\"" +
                                "    }" +
                                "  }" +
                                "}")));

        DecisionResult decision = securityService.getDecision("deprecated-and-young-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_DEPRECATION");
    }

    @Test
    void shouldAllowWhenMavenHeadReturnsNoLastModifiedHeader() {
        // Maven HEAD retourne 200 mais sans header Last-Modified → RegistryClient retourne
        // Optional.empty() → SecurityService tombe en fail-open (REGISTRY_ERROR ALLOW).
        wireMock.stubFor(com.github.tomakehurst.wiremock.client.WireMock
                .head(com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo(
                        "/maven2/com/example/no-last-modified-lib/1.0.0/"))
                .willReturn(aResponse().withStatus(200)));

        DecisionResult decision = securityService.getDecision(
                "com.example:no-last-modified-lib", "1.0.0", "maven");

        assertThat(decision.result()).isEqualTo("ALLOW");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_ERROR");
    }

    @Test
    void shouldUseDefaultSeverityThresholdForUnknownEcosystem() {
        // "golang" is not in the severity config → uses default values :
        // defaultMaxAllowedSeverity=MEDIUM → getSeverityPlancher(MEDIUM)=7.0
        // defaultMaxAllowedCvss=7.0 → minCvss = min(7.0, 7.0) = 7.0
        // A package with CVSS 7.5 >= 7.0 must be blocked (spec §4.2).
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score)
                VALUES ('CVE-default-sev', 'OSV', 'golang-vuln-pkg', 'golang', 'Security issue', '["1.0.0"]'::jsonb, 7.5)
                """).update();

        DecisionResult decision = securityService.getDecision("golang-vuln-pkg", "1.0.0", "golang");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("PUBLIC_VULN");
    }

    @Test
    void shouldBlockDeprecatedPackageWithNullReason() {
        // npm returns "deprecated": null in the version JSON → isDeprecated=true, deprecationReason=null.
        // SecurityService must use the default message "The package is deprecated or removed (yanked)."
        // (spec §4.3 step 2, SecurityService L113).
        Instant publishedAt = Instant.now().minus(10, ChronoUnit.DAYS);
        wireMock.stubFor(get(urlEqualTo("/null-reason-pkg"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{" +
                                "  \"time\": {\"1.0.0\": \"" + publishedAt.toString() + "\"}," +
                                "  \"versions\": {" +
                                "    \"1.0.0\": {" +
                                "      \"name\": \"null-reason-pkg\"," +
                                "      \"version\": \"1.0.0\"," +
                                "      \"deprecated\": null" +
                                "    }" +
                                "  }" +
                                "}")));

        DecisionResult decision = securityService.getDecision("null-reason-pkg", "1.0.0", "npm");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_DEPRECATION");
        assertThat(decision.reason()).isEqualTo("The package is deprecated or removed (yanked).");
    }

    @Test
    void shouldUseDefaultMinAgeDaysForUnknownEcosystem() {
        // For an unknown ecosystem (not listed in quarantine.ecosystems), quarantine
        // applies with defaultMinAgeDays=7. A package published 3 days ago (3 < 7) must
        // be blocked (spec §4.3 step 3, SecurityService L241).
        // The date is pre-loaded in package_metadata to avoid a registry call
        // (the registry does not know "golang").
        Instant publishedAt = Instant.now().minus(3, ChronoUnit.DAYS);
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES ('unknown-eco-pkg', 'golang', '1.0.0', ?)
                """).params(java.sql.Timestamp.from(publishedAt)).update();

        DecisionResult decision = securityService.getDecision("unknown-eco-pkg", "1.0.0", "golang");

        assertThat(decision.result()).isEqualTo("BLOCK");
        assertThat(decision.sourceType()).isEqualTo("REGISTRY_QUARANTINE");
        assertThat(decision.reason()).contains("3");
    }
}
