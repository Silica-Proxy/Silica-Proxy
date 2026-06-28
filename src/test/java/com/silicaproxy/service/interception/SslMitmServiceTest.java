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

import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

@NullMarked
class SslMitmServiceTest {

    @TempDir
    Path tempDir;

    private SilicaProxyProperties makeProperties(@Nullable String keystorePath, @Nullable String password) {
        return new SilicaProxyProperties(
            new SilicaProxyProperties.QuarantineProperties(false, 0, true, Map.of()),
            new SilicaProxyProperties.DeprecationProperties(false, Map.of()),
            new SilicaProxyProperties.SeverityThresholdProperties(false, "NONE", 11.0, Map.of()),
            Map.of(),
            new SilicaProxyProperties.GitOpsProperties(false, "http://example.com", "/rules", null, 60),
            new SilicaProxyProperties.CorporateProxyProperties(false, "proxy.example.com", 8080, "localhost",
                new SilicaProxyProperties.CorporateProxyScopeProperties(false, false, false, false)),
            new SilicaProxyProperties.RegistriesProperties("http://npm.example.com", "http://pypi.example.com", "http://maven.example.com"),
            new SilicaProxyProperties.ProxyProperties(0),
            new SilicaProxyProperties.SecurityProperties(new SilicaProxyProperties.SsrfProtectionProperties(false)),
            new SilicaProxyProperties.HttpClientProperties(5, 5, 5),
            new SilicaProxyProperties.SslMitmProperties(keystorePath, password, null),
            new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
            new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
            new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100)
        );
    }

    @Test
    void shouldGetCaCertPem() throws Exception {
        var service = new SslMitmService(makeProperties(null, null), new MitmCertificateFactory());
        service.init();

        assertThat(service.getCaCertPem())
            .startsWith("-----BEGIN CERTIFICATE-----")
            .contains("-----END CERTIFICATE-----");
    }

    @Test
    void shouldGenerateAndSaveKeystoreWhenPathNotExists() throws Exception {
        Path keystorePath = tempDir.resolve("ca.p12");
        var service = new SslMitmService(makeProperties(keystorePath.toString(), null), new MitmCertificateFactory());
        service.init();

        assertThat(keystorePath).exists();
        assertThat(service.getCaCertPem()).startsWith("-----BEGIN CERTIFICATE-----");
    }

    @Test
    void shouldGenerateAndSaveKeystoreWithPassword() throws Exception {
        Path keystorePath = tempDir.resolve("ca-pwd.p12");
        var service = new SslMitmService(makeProperties(keystorePath.toString(), "changeit"), new MitmCertificateFactory());
        service.init();

        assertThat(keystorePath).exists();
        assertThat(service.getCaCertPem()).startsWith("-----BEGIN CERTIFICATE-----");
    }

    @Test
    void shouldLoadCaFromExistingKeystore() throws Exception {
        Path keystorePath = tempDir.resolve("ca.p12");
        MitmCertificateFactory factory = new MitmCertificateFactory();

        var service1 = new SslMitmService(makeProperties(keystorePath.toString(), "changeit"), factory);
        service1.init();
        String pemFirst = service1.getCaCertPem();

        var service2 = new SslMitmService(makeProperties(keystorePath.toString(), "changeit"), factory);
        service2.init();

        assertThat(service2.getCaCertPem()).isEqualTo(pemFirst);
    }

    @Test
    void shouldCacheSSLContextPerHost() throws Exception {
        var service = new SslMitmService(makeProperties(null, null), new MitmCertificateFactory());
        service.init();

        var ctx1 = service.getContextForHost("example.com");
        var ctx2 = service.getContextForHost("example.com");

        assertThat(ctx1).isSameAs(ctx2);
    }

    @Test
    void shouldWrapExceptionInGetContextForHost() throws Exception {
        MitmCertificateFactory factory = spy(new MitmCertificateFactory());
        doCallRealMethod()
            .doThrow(new RuntimeException("key gen failed"))
            .when(factory)
            .generateKeyPair();

        var service = new SslMitmService(makeProperties(null, null), factory);
        service.init();

        assertThatThrownBy(() -> service.getContextForHost("fail.com"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("SSL context generation failed for fail.com");
    }
}
