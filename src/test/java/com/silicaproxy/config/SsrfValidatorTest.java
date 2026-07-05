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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SsrfValidatorTest {

    private static SilicaProxyProperties makeProperties() {
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
                new SilicaProxyProperties.SsrfProtectionProperties(true),
                new SilicaProxyProperties.ApiAuthProperties(false, null, null)),
            new SilicaProxyProperties.HttpClientProperties(5, 5, 5, 1),
            new SilicaProxyProperties.SslMitmProperties(null, null, null, 2000),
            new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
            new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
            new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100),
            new SilicaProxyProperties.ExternalValidationProperties(null, false, Map.of())
        );
    }

    private final SsrfValidator validator = new SsrfValidator(makeProperties());

    @Test
    void shouldFailClosedWhenUrlHasNoHost() {
        assertThatThrownBy(() -> validator.validateUrl("file:///etc/passwd"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");
    }

    @Test
    void shouldBlockUniqueLocalIpv6Address() {
        assertThatThrownBy(() -> validator.validateUrl("http://[fc00::1]/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");

        assertThatThrownBy(() -> validator.validateUrl("http://[fd00::1]/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");
    }

    @Test
    void shouldBlockCarrierGradeNatAddress() {
        assertThatThrownBy(() -> validator.validateUrl("http://100.64.0.1/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");

        assertThatThrownBy(() -> validator.validateUrl("http://100.100.0.1/internal"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SSRF Blocked");
    }

    @Test
    void shouldAllowAddressesJustOutsideCarrierGradeNatRange() {
        // 100.63.255.255 is just below 100.64.0.0/10 ; 100.128.0.0 is just above it.
        validator.validateUrl("http://100.63.255.255/external");
        validator.validateUrl("http://100.128.0.0/external");
    }

    @Test
    void shouldAllowPublicAddresses() {
        validator.validateUrl("http://8.8.8.8/external");
    }

    @Test
    void shouldSkipValidationWhenDisabled() {
        SsrfValidator disabled = new SsrfValidator(makeProperties());
        disabled.setEnabled(false);
        // Would normally be blocked (loopback), but validation is disabled.
        disabled.validateUrl("http://127.0.0.1/internal");
    }
}
