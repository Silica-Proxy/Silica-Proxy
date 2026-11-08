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
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// External validation — async mode, fail-closed, blocking : a service that already knows the
// package answers its verdict in the trigger acknowledgment, applied to the very first request.
class ExternalValidationAsyncImmediateVerdictTest extends BaseIntegrationTest {

    private static final String SERVICE_NAME = "test-scanner";
    private static final String ARTIFACT = "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ExternalValidationCacheDao cacheDao;

    @Autowired
    private ExternalValidationVerdictsDao verdictsDao;

    @Autowired
    private MeterRegistry meterRegistry;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    private RestClient proxyRestClient;
    private RestClient localRestClient;

    @DynamicPropertySource
    static void configureExternalValidation(DynamicPropertyRegistry registry) {
        String extUrl = "http://localhost:" + wireMock.port() + "/external-validate";
        registry.add("silicaproxy.external-validation.callback-base-url", () -> "http://localhost:0");
        String servicePrefix = "silicaproxy.external-validation.services." + SERVICE_NAME + ".";
        registry.add(servicePrefix + "enabled", () -> "true");
        registry.add(servicePrefix + "url", () -> extUrl);
        registry.add(servicePrefix + "mode", () -> Metrics.TYPE_ASYNC);
        registry.add(servicePrefix + "fail-open", () -> "false");
        registry.add(servicePrefix + "blocking", () -> "true");
        registry.add(servicePrefix + "cache-ttl-minutes", () -> "60");
        registry.add(servicePrefix + "pending-ttl-minutes", () -> "30");
        registry.add("silicaproxy.quarantine.enabled", () -> "false");
        registry.add("silicaproxy.deprecation.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.osv.enabled", () -> "false");
        registry.add("silicaproxy.api-fallback.deps-dev.enabled", () -> "false");
    }

    @BeforeEach
    void setUp() throws Exception {
        jdbcClient.sql("TRUNCATE company_policies RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE public_vulnerabilities RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE api_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE package_metadata RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("""
                INSERT INTO package_metadata (package_name, ecosystem, package_version, published_at)
                VALUES ('lodash', 'npm', '4.17.21', NOW() - INTERVAL '365 days')
                """).update();
        jdbcClient.sql("TRUNCATE external_validation_cache RESTART IDENTITY CASCADE").update();
        jdbcClient.sql("TRUNCATE external_validation_verdicts RESTART IDENTITY CASCADE").update();
        wireMock.resetAll();

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));
        proxyRestClient = RestClient.builder().requestFactory(factory).build();
        localRestClient = RestClient.create("http://localhost:" + port);

        when(proxyStreamClient.streamContent(any(), any()))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream("fake-content".getBytes())));
    }

    @Test
    void allowedInAcknowledgment_firstRequestForwardedAndCached() {
        stubAck(200, MediaType.APPLICATION_JSON_VALUE,
                "{\"status\":\"DONE\",\"verdict\":\"ALLOWED\",\"reason\":\"No findings\"}");
        double allowedBefore = callCount(Metrics.ALLOWED);
        double triggeredBefore = callCount(Metrics.RESULT_TRIGGERED);

        ResponseEntity<byte[]> response = proxyRestClient.get().uri(ARTIFACT).retrieve().toEntity(byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ExternalValidationCacheEntry entry = cacheEntry();
        assertThat(entry.status()).isEqualTo(Metrics.ALLOWED);
        assertThat(callCount(Metrics.ALLOWED) - allowedBefore).isEqualTo(1.0);
        assertThat(callCount(Metrics.RESULT_TRIGGERED) - triggeredBefore).isEqualTo(1.0);
        // A vetted ALLOW : the final decision is cached
        assertThat(jdbcClient.sql("SELECT api_source FROM api_cache WHERE package_name = 'lodash'")
                .query(String.class).single()).isEqualTo("EXTERNAL_VALIDATION_CHAIN");

        // The callback the service still sends afterwards finds the token resolved
        HttpClientErrorException late = catchThrowableOfType(HttpClientErrorException.class,
                () -> callback(entry.callbackToken(), "ALLOWED"));
        assertThat(late.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        // Second request : no new trigger
        proxyRestClient.get().uri(ARTIFACT).retrieve().toBodilessEntity();
        wireMock.verify(exactly(1), postRequestedFor(urlEqualTo("/external-validate")));
    }

    @Test
    void blockedInAcknowledgment_firstRequestBlockedPermanently() {
        stubAck(200, MediaType.APPLICATION_JSON_VALUE,
                "{\"status\":\"DONE\",\"verdict\":\"BLOCKED\",\"reason\":\"Install script exfiltrates env\"}");

        HttpClientErrorException e = catchThrowableOfType(HttpClientErrorException.class,
                () -> proxyRestClient.get().uri(ARTIFACT).retrieve().toBodilessEntity());

        assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(e.getResponseBodyAsString()).contains("Install script exfiltrates env");
        assertThat(verdictsDao.findByServiceAndPackage(SERVICE_NAME, "lodash", "npm", "4.17.21")).isPresent();
        assertThat(cacheDao.findByServiceAndPackage(SERVICE_NAME, "lodash", "npm", "4.17.21")).isEmpty();
    }

    @Test
    void pendingAcknowledgment_returns429AndWaitsForCallback() {
        stubAck(202, MediaType.APPLICATION_JSON_VALUE, "{\"status\":\"PENDING\",\"verdict\":null}");

        assertPending();

        // The callback then resolves it
        callback(cacheEntry().callbackToken(), "ALLOWED");
        ResponseEntity<byte[]> response = proxyRestClient.get().uri(ARTIFACT).retrieve().toEntity(byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void nonJsonAcknowledgment_isAPlainAcknowledgment() {
        double triggeredBefore = callCount(Metrics.RESULT_TRIGGERED);
        stubAck(200, MediaType.TEXT_PLAIN_VALUE, "Accepted");

        assertPending();
        assertThat(callCount(Metrics.RESULT_TRIGGERED) - triggeredBefore).isEqualTo(1.0);
    }

    @Test
    void unknownVerdictInAcknowledgment_isIgnored() {
        stubAck(200, MediaType.APPLICATION_JSON_VALUE, "{\"verdict\":\"MAYBE\"}");

        assertPending();
    }

    private void assertPending() {
        HttpClientErrorException e = catchThrowableOfType(HttpClientErrorException.class,
                () -> proxyRestClient.get().uri(ARTIFACT).retrieve().toBodilessEntity());
        assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(e.getResponseBodyAsString()).contains("\"step\":\"EXTERNAL_VALIDATION_PENDING\"");
        assertThat(cacheEntry().status()).isEqualTo("PENDING");
    }

    private void stubAck(int status, String contentType, String body) {
        wireMock.stubFor(post(urlEqualTo("/external-validate"))
                .willReturn(aResponse().withStatus(status)
                        .withHeader(HttpHeaders.CONTENT_TYPE, contentType)
                        .withBody(body)));
    }

    private ExternalValidationCacheEntry cacheEntry() {
        return cacheDao.findByServiceAndPackage(SERVICE_NAME, "lodash", "npm", "4.17.21").orElseThrow();
    }

    private void callback(UUID token, String verdict) {
        localRestClient.post()
                .uri("/external-validation/callback/" + token)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"verdict\":\"" + verdict + "\",\"reason\":\"late\"}")
                .retrieve().toBodilessEntity();
    }

    private double callCount(String result) {
        Counter counter = meterRegistry.find(Metrics.VALIDATION_CALLS_METRIC)
                .tag(Metrics.TAG_SERVICE, SERVICE_NAME)
                .tag(Metrics.TAG_TYPE, Metrics.TYPE_ASYNC)
                .tag(Metrics.TAG_RESULT, result)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }
}
