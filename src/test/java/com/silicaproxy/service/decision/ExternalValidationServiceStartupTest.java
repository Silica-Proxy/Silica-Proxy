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
import com.silicaproxy.dao.client.ExternalValidationClient;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit test (no Spring context) for the fail-fast startup check in
 * {@link ExternalValidationService#logConfiguredServices()} : a blank
 * {@code callback-base-url} is only a problem when at least one configured service is
 * {@code mode=ASYNC} (its callback URL is never built for a SYNC-only deployment).
 */
class ExternalValidationServiceStartupTest {

    private static SilicaProxyProperties makeProperties(
            @org.jspecify.annotations.Nullable String callbackBaseUrl, String serviceMode) {
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
                new SilicaProxyProperties.ApiAuthProperties(false, null, null)),
            new SilicaProxyProperties.HttpClientProperties(5, 5, 5, 1),
            new SilicaProxyProperties.SslMitmProperties(null, null, null, 2000),
            new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
            new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
            new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100),
            new SilicaProxyProperties.ExternalValidationProperties(callbackBaseUrl, false, Map.of(
                "test-service", new SilicaProxyProperties.ExternalValidationServiceProperties(
                    true, "http://example.com/validate", null, serviceMode, 1, true, true, 60, 30)))
        );
    }

    private ExternalValidationService makeService(SilicaProxyProperties properties) {
        return new ExternalValidationService(
                properties,
                mock(ExternalValidationCacheDao.class),
                mock(ExternalValidationVerdictsDao.class),
                mock(ExternalValidationClient.class),
                mock(Executor.class),
                mock(ExternalValidationMetrics.class));
    }

    @Test
    void shouldFailFastWhenAsyncServiceConfiguredWithBlankCallbackBaseUrl() {
        ExternalValidationService service = makeService(makeProperties(null, Metrics.TYPE_ASYNC));

        assertThatThrownBy(service::logConfiguredServices)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("callback-base-url");
    }

    @Test
    void shouldFailFastWhenAsyncServiceConfiguredWithEmptyCallbackBaseUrl() {
        ExternalValidationService service = makeService(makeProperties("", Metrics.TYPE_ASYNC));

        assertThatThrownBy(service::logConfiguredServices)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("callback-base-url");
    }

    @Test
    void shouldStartSuccessfullyWhenOnlySyncServicesConfiguredWithBlankCallbackBaseUrl() {
        ExternalValidationService service = makeService(makeProperties(null, Metrics.TYPE_SYNC));

        assertThatCode(service::logConfiguredServices).doesNotThrowAnyException();
    }

    @Test
    void shouldStartSuccessfullyWhenAsyncServiceConfiguredWithNonBlankCallbackBaseUrl() {
        ExternalValidationService service = makeService(makeProperties("http://proxy.example.com", Metrics.TYPE_ASYNC));

        assertThatCode(service::logConfiguredServices).doesNotThrowAnyException();
    }
}
