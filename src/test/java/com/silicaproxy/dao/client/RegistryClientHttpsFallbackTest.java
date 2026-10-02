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


package com.silicaproxy.dao.client;

import com.silicaproxy.config.SsrfInterceptor;
import com.silicaproxy.model.dto.RegistryLookup;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.interception.HttpsUpgradePolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import tools.jackson.databind.json.JsonMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/** The intercepted-URL fallback must be looked up like the relay : https:// unless the host is http-only. */
class RegistryClientHttpsFallbackTest {

    private static final String CENTRAL = "https://repo1.maven.org";
    private static final String LAST_MODIFIED = "Tue, 22 Sep 2026 00:27:17 GMT";

    private final List<String> calls = new ArrayList<>();
    private RegistryClient client;

    @BeforeEach
    void setUp() throws Exception {
        // Maven Central never knows the artifact (a Gradle plugin marker) ; any other URL answers 200.
        ClientHttpRequestFactory factory = (uri, method) -> {
            calls.add(method + " " + uri);
            MockClientHttpResponse response = uri.toString().startsWith(CENTRAL)
                    ? new MockClientHttpResponse(new byte[0], HttpStatus.NOT_FOUND)
                    : new MockClientHttpResponse(new byte[0], HttpStatus.OK);
            response.getHeaders().set("Last-Modified", LAST_MODIFIED);
            MockClientHttpRequest request = new MockClientHttpRequest(method, uri);
            request.setResponse(response);
            return request;
        };
        SsrfInterceptor passThrough = mock(SsrfInterceptor.class);
        doAnswer(invocation -> ((ClientHttpRequestExecution) invocation.getArgument(2))
                .execute(invocation.getArgument(0), invocation.getArgument(1)))
                .when(passThrough).intercept(any(), any(), any());
        client = new RegistryClient(properties(), factory, passThrough, new JsonMapper());
    }

    private static SilicaProxyProperties properties() {
        return new SilicaProxyProperties(
                new SilicaProxyProperties.QuarantineProperties(false, 0, true, Map.of()),
                new SilicaProxyProperties.DeprecationProperties(false, Map.of()),
                new SilicaProxyProperties.SeverityThresholdProperties(false, "NONE", 11.0, Map.of()),
                Map.of(),
                new SilicaProxyProperties.GitOpsProperties(false, "http://example.com", "/rules", null, 60),
                new SilicaProxyProperties.CorporateProxyProperties(false, "proxy.example.com", 8080, "localhost",
                        new SilicaProxyProperties.CorporateProxyScopeProperties(false, false, false, false, false)),
                new SilicaProxyProperties.RegistriesProperties("https://registry.npmjs.org", "https://pypi.org", CENTRAL),
                new SilicaProxyProperties.ProxyProperties(0, 30, 60),
                new SilicaProxyProperties.SecurityProperties(
                        new SilicaProxyProperties.SsrfProtectionProperties(false),
                        new SilicaProxyProperties.ApiAuthProperties(false, null, null)),
                new SilicaProxyProperties.HttpClientProperties(5, 5, 5, 1),
                new SilicaProxyProperties.SslMitmProperties(null, null, null, 2000),
                new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
                new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
                new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100),
                new SilicaProxyProperties.ExternalValidationProperties(null, false, Map.of()));
    }

    private RegistryLookup lookup(String fullUrl) {
        return client.lookupMaven("com.acme:plugin", "1.0", fullUrl);
    }

    @Test
    void fallbackToAnHttpUrlIsLookedUpInHttps() {
        RegistryLookup result = lookup("http://plugins.gradle.org/m2/com/acme/plugin/1.0/plugin-1.0.pom");

        assertThat(result.status()).isEqualTo(RegistryLookup.Status.FOUND);
        assertThat(calls).contains("HEAD https://plugins.gradle.org/m2/com/acme/plugin/1.0/plugin-1.0.pom")
                .noneMatch(call -> call.contains("http://plugins.gradle.org"));
    }

    @Test
    void fallbackToAnHttpOnlyHostStaysInHttp() {
        client.setHttpsUpgradePolicy(HttpsUpgradePolicy.fromCsv("plugins.gradle.org"));

        RegistryLookup result = lookup("http://plugins.gradle.org/m2/com/acme/plugin/1.0/plugin-1.0.pom");

        assertThat(result.status()).isEqualTo(RegistryLookup.Status.FOUND);
        assertThat(calls).contains("HEAD http://plugins.gradle.org/m2/com/acme/plugin/1.0/plugin-1.0.pom");
    }

    @Test
    void fallbackDropsTheServerPortThatLeakedIntoTheUrl() {
        client.setHttpsUpgradePolicy(HttpsUpgradePolicy.fromCsv("", 8089));

        lookup("http://plugins.gradle.org:8089/m2/com/acme/plugin/1.0/plugin-1.0.pom");

        assertThat(calls).contains("HEAD https://plugins.gradle.org/m2/com/acme/plugin/1.0/plugin-1.0.pom");
    }

    @Test
    void mavenCentralIsAskedFirstAndBlankFallbackIsNotUpgraded() {
        RegistryLookup result = lookup("");

        assertThat(result.status()).isEqualTo(RegistryLookup.Status.NOT_FOUND);
        assertThat(calls).containsExactly("HEAD " + CENTRAL + "/maven2/com/acme/plugin/1.0/");
    }
}
