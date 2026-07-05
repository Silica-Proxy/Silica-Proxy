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


package com.silicaproxy.config;

import com.silicaproxy.properties.SilicaProxyProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeyValidatorTest {

    private static SilicaProxyProperties makeProperties(boolean enabled, String keyRead, String keyAction) {
        return new SilicaProxyProperties(
            new SilicaProxyProperties.QuarantineProperties(false, 0, true, Map.of()),
            new SilicaProxyProperties.DeprecationProperties(false, Map.of()),
            new SilicaProxyProperties.SeverityThresholdProperties(false, "NONE", 11.0, Map.of()),
            Map.of(),
            new SilicaProxyProperties.GitOpsProperties(false, "http://example.com", "/rules", null, 60),
            new SilicaProxyProperties.CorporateProxyProperties(false, "proxy.example.com", 8080, "localhost",
                new SilicaProxyProperties.CorporateProxyScopeProperties(false, false, false, false, false)),
            new SilicaProxyProperties.RegistriesProperties("http://npm.example.com", "http://pypi.example.com", "http://maven.example.com"),
            new SilicaProxyProperties.ProxyProperties(0, 30, 60),
            new SilicaProxyProperties.SecurityProperties(
                new SilicaProxyProperties.SsrfProtectionProperties(false),
                new SilicaProxyProperties.ApiAuthProperties(enabled, keyRead, keyAction)),
            new SilicaProxyProperties.HttpClientProperties(5, 5, 5, 1),
            new SilicaProxyProperties.SslMitmProperties(null, null, null),
            new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
            new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
            new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100),
            new SilicaProxyProperties.ExternalValidationProperties(null, false, Map.of())
        );
    }

    @Test
    void shouldAuthorizeAnyKeyWhenDisabled() {
        ApiKeyValidator validator = new ApiKeyValidator(makeProperties(false, "read-key", "action-key"));

        assertThat(validator.isAuthorized(ApiKeyScope.READ, null)).isTrue();
        assertThat(validator.isAuthorized(ApiKeyScope.READ, "wrong-key")).isTrue();
        assertThat(validator.isAuthorized(ApiKeyScope.ACTION, null)).isTrue();
    }

    @Test
    void shouldAuthorizeReadScopeWithEitherReadOrActionKey() {
        ApiKeyValidator validator = new ApiKeyValidator(makeProperties(true, "read-key", "action-key"));

        assertThat(validator.isAuthorized(ApiKeyScope.READ, "read-key")).isTrue();
        // ACTION is a superset of READ: an action key can also authenticate read-only calls.
        assertThat(validator.isAuthorized(ApiKeyScope.READ, "action-key")).isTrue();
        assertThat(validator.isAuthorized(ApiKeyScope.READ, "wrong-key")).isFalse();
        assertThat(validator.isAuthorized(ApiKeyScope.READ, null)).isFalse();
    }

    @Test
    void shouldAuthorizeActionScopeWithMatchingActionKeyOnly() {
        ApiKeyValidator validator = new ApiKeyValidator(makeProperties(true, "read-key", "action-key"));

        assertThat(validator.isAuthorized(ApiKeyScope.ACTION, "action-key")).isTrue();
        // READ is not a superset of ACTION: a read key must not unlock side-effecting endpoints.
        assertThat(validator.isAuthorized(ApiKeyScope.ACTION, "read-key")).isFalse();
        assertThat(validator.isAuthorized(ApiKeyScope.ACTION, "wrong-key")).isFalse();
        assertThat(validator.isAuthorized(ApiKeyScope.ACTION, null)).isFalse();
    }

    @Test
    void shouldFailClosedWhenEnabledButKeyNotConfigured() {
        ApiKeyValidator validator = new ApiKeyValidator(makeProperties(true, null, ""));

        assertThat(validator.isAuthorized(ApiKeyScope.READ, null)).isFalse();
        assertThat(validator.isAuthorized(ApiKeyScope.READ, "anything")).isFalse();
        assertThat(validator.isAuthorized(ApiKeyScope.ACTION, "")).isFalse();
    }

    @Test
    void setEnabledShouldOverrideConfiguredValue() {
        ApiKeyValidator validator = new ApiKeyValidator(makeProperties(true, "read-key", "action-key"));

        validator.setEnabled(false);
        assertThat(validator.isAuthorized(ApiKeyScope.READ, "wrong-key")).isTrue();

        validator.setEnabled(true);
        assertThat(validator.isAuthorized(ApiKeyScope.READ, "wrong-key")).isFalse();
    }
}
