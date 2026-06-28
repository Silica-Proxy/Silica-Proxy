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


package com.silicaproxy.service.search;

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.service.search.PackageSearchService.SearchResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class PackageSearchServiceTest extends BaseIntegrationTest {

    private final PackageSearchService packageSearchService;
    private final JdbcClient jdbcClient;

    @Autowired
    PackageSearchServiceTest(PackageSearchService packageSearchService, JdbcClient jdbcClient) {
        this.packageSearchService = packageSearchService;
        this.jdbcClient = jdbcClient;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
    }

    @Test
    void shouldReturnEmptyResultWhenPackageIsUnknown() {
        SearchResult result = packageSearchService.search("unknown-pkg", null, null, null);

        assertThat(result.found()).isFalse();
        assertThat(result.companyPolicies()).isEmpty();
        assertThat(result.publicVulnerabilities()).isEmpty();
        assertThat(result.apiCacheEntries()).isEmpty();
    }

    @Test
    void shouldFindCompanyPolicyByExactVersionMatchingWildcardPattern() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '4.%', 'WHITELIST', 'Approved', 'admin')
                """).update();

        SearchResult match = packageSearchService.search("lodash", "npm", "4.17.21", null);
        assertThat(match.found()).isTrue();
        assertThat(match.companyPolicies()).hasSize(1);
        assertThat(match.companyPolicies().get(0).policyAction()).isEqualTo("WHITELIST");

        SearchResult noMatch = packageSearchService.search("lodash", "npm", "3.0.0", null);
        assertThat(noMatch.companyPolicies()).isEmpty();
    }

    @Test
    void shouldFindCompanyPolicyByRegexOnVersionPattern() {
        jdbcClient.sql("""
                INSERT INTO company_policies (package_name, ecosystem, version_pattern, policy_action, reason, updated_by)
                VALUES ('lodash', 'npm', '4.%', 'WHITELIST', 'Approved', 'admin')
                """).update();

        SearchResult result = packageSearchService.search("lodash", null, null, "^4\\.");
        assertThat(result.companyPolicies()).hasSize(1);
    }

    @Test
    void shouldFindPublicVulnerabilityWithMatchedVersionsSubset() {
        jdbcClient.sql("""
                INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, affected_versions, cvss_score, published_at)
                VALUES ('GHSA-test-1', 'OSV', 'event-stream', 'npm', 'Compromised package', '["3.3.6", "3.3.7", "4.0.0"]'::jsonb, 9.8, ?)
                """).params(Timestamp.from(Instant.now().minus(100, ChronoUnit.DAYS))).update();

        SearchResult exact = packageSearchService.search("event-stream", "npm", "3.3.6", null);
        assertThat(exact.publicVulnerabilities()).hasSize(1);
        assertThat(exact.publicVulnerabilities().get(0).source()).isEqualTo("OSV");
        assertThat(exact.publicVulnerabilities().get(0).matchedVersions()).containsExactly("3.3.6");

        SearchResult regex = packageSearchService.search("event-stream", null, null, "^3\\.3\\.");
        assertThat(regex.publicVulnerabilities()).hasSize(1);
        assertThat(regex.publicVulnerabilities().get(0).matchedVersions())
                .containsExactlyInAnyOrder("3.3.6", "3.3.7");

        SearchResult noMatch = packageSearchService.search("event-stream", null, "9.9.9", null);
        assertThat(noMatch.publicVulnerabilities()).isEmpty();
    }

    @Test
    void shouldFindApiCacheEntryAndFlagExpiredOnes() {
        jdbcClient.sql("""
                INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
                VALUES ('safe-pkg', 'npm', '1.0.0', true, 'OSV_LIVE', ?)
                """).params(Timestamp.from(Instant.now().plus(1, ChronoUnit.DAYS))).update();
        jdbcClient.sql("""
                INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
                VALUES ('safe-pkg', 'npm', '0.9.0', true, 'PHYLUM', ?)
                """).params(Timestamp.from(Instant.now().minus(1, ChronoUnit.DAYS))).update();

        SearchResult result = packageSearchService.search("safe-pkg", null, null, null);
        assertThat(result.apiCacheEntries()).hasSize(2);

        SearchResult fresh = packageSearchService.search("safe-pkg", null, "1.0.0", null);
        assertThat(fresh.apiCacheEntries()).hasSize(1);
        assertThat(fresh.apiCacheEntries().get(0).apiSource()).isEqualTo("OSV_LIVE");
        assertThat(fresh.apiCacheEntries().get(0).expired()).isFalse();

        SearchResult expired = packageSearchService.search("safe-pkg", null, "0.9.0", null);
        assertThat(expired.apiCacheEntries().get(0).expired()).isTrue();
    }

    @Test
    void shouldRejectBothVersionAndVersionRegexAtControllerLevelButServiceAllowsCallerToChoose() {
        // The service itself does not enforce exclusivity (it is the controller's responsibility) ;
        // if both are provided, exactVersion simply wins as an additional filter.
        jdbcClient.sql("""
                INSERT INTO api_cache (package_name, ecosystem, package_version, is_secure, api_source, expires_at)
                VALUES ('pkg', 'npm', '1.0.0', true, 'OSV_LIVE', ?)
                """).params(Timestamp.from(Instant.now().plus(1, ChronoUnit.DAYS))).update();

        SearchResult result = packageSearchService.search("pkg", null, "1.0.0", "^1\\.");
        assertThat(result.apiCacheEntries()).hasSize(1);
    }
}
