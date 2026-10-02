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


package com.silicaproxy.service.interception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class HttpsUpgradePolicyTest {

    private static final int LOCAL_PORT = 8089;

    @Test
    void upgradesRemoteHttpUrlToHttps() {
        assertThat(HttpsUpgradePolicy.upgradeAll().upgrade("http://plugins.gradle.org/m2/a/b.pom", LOCAL_PORT))
                .isEqualTo("https://plugins.gradle.org/m2/a/b.pom");
    }

    @Test
    void keepsQueryStringWhenUpgrading() {
        assertThat(HttpsUpgradePolicy.upgradeAll().upgrade("http://example.com/p?x=1&y=2", LOCAL_PORT))
                .isEqualTo("https://example.com/p?x=1&y=2");
    }

    @Test
    void keepsGenuinePortButDropsTheConnectorPort() {
        HttpsUpgradePolicy policy = HttpsUpgradePolicy.upgradeAll();

        assertThat(policy.upgrade("http://mirror.local:8443/p", LOCAL_PORT)).isEqualTo("https://mirror.local:8443/p");
        assertThat(policy.upgrade("http://mirror.local:8089/p", LOCAL_PORT)).isEqualTo("https://mirror.local/p");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:8080/p", "http://127.0.0.1/p", "http://host.docker.internal/p",
            "https://plugins.gradle.org/p", "not-a-url"})
    void leavesLocalHostsAndNonHttpUrlsUntouched(String url) {
        assertThat(HttpsUpgradePolicy.upgradeAll().upgrade(url, LOCAL_PORT)).isEqualTo(url);
    }

    @Test
    void leavesConfiguredHttpOnlyHostsOnHttp() {
        HttpsUpgradePolicy policy = HttpsUpgradePolicy.fromCsv("plugins.gradle.org,internal.registry");

        assertThat(policy.upgrade("http://plugins.gradle.org/m2/a.pom", LOCAL_PORT))
                .isEqualTo("http://plugins.gradle.org/m2/a.pom");
        assertThat(policy.upgrade("http://internal.registry:8081/r/a.jar", LOCAL_PORT))
                .isEqualTo("http://internal.registry:8081/r/a.jar");
        assertThat(policy.upgrade("http://repo1.maven.org/maven2/a.pom", LOCAL_PORT))
                .isEqualTo("https://repo1.maven.org/maven2/a.pom");
    }

    @Test
    void httpOnlyHostsAreTrimmedAndCaseInsensitive() {
        HttpsUpgradePolicy policy = HttpsUpgradePolicy.fromCsv("  Plugins.Gradle.ORG  , ,other.host ");

        assertThat(policy.upgrade("http://plugins.gradle.org/a", LOCAL_PORT)).isEqualTo("http://plugins.gradle.org/a");
        assertThat(policy.upgrade("http://PLUGINS.gradle.org/a", LOCAL_PORT)).isEqualTo("http://PLUGINS.gradle.org/a");
        assertThat(policy.upgrade("http://other.host/a", LOCAL_PORT)).isEqualTo("http://other.host/a");
    }

    @Test
    void emptyHttpOnlyHostsUpgradesEverything() {
        assertThat(HttpsUpgradePolicy.fromCsv("").upgrade("http://example.com/a", LOCAL_PORT))
                .isEqualTo("https://example.com/a");
        assertThat(HttpsUpgradePolicy.fromCsv(" , ").upgrade("http://example.com/a", LOCAL_PORT))
                .isEqualTo("https://example.com/a");
    }
}
