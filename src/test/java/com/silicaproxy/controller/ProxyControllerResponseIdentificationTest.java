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

package com.silicaproxy.controller;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.dao.npm.NpmTarballIndexDao;
import com.silicaproxy.dao.sync.HealthCheckDao;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.HashType;
import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.ChecksumVerifyingRelay.ChecksumMismatchException;
import com.silicaproxy.service.interception.ExpectedDigest;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import com.silicaproxy.service.interception.PackageIdentificationService;
import com.silicaproxy.service.interception.ParsedPackage;
import com.silicaproxy.service.interception.ResponseIdentificationService;
import com.silicaproxy.service.interception.ResponseIdentificationService.ResponseIdentification;
import com.silicaproxy.service.interception.UrlParserService;
import com.silicaproxy.service.monitoring.DatabaseAvailabilityService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A request its URL does not identify is identified from the file digest the upstream response
 * announces : the package found goes through the security decision, and an allowed body is only
 * relayed in full when its recomputed digest matches.
 */
class ProxyControllerResponseIdentificationTest {

    private static final String URL = "http://repo.corp.example/api/download/blob/4f2a91";
    private static final String FORWARD_URL = "https://repo.corp.example/api/download/blob/4f2a91";
    private static final ParsedPackage PKG = new ParsedPackage("org.example:lib", "1.0.0", "maven");

    private final SecurityService securityService = mock(SecurityService.class);
    private final AuditLogService auditLogService = mock(AuditLogService.class);
    private final ProxyStreamClient proxyStreamClient = mock(ProxyStreamClient.class);
    private final UrlParserService urlParserService = mock(UrlParserService.class);
    private final ResponseIdentificationService responseIdentification = mock(ResponseIdentificationService.class);
    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    private final NpmPackumentIndexProperties npmProperties =
            new NpmPackumentIndexProperties(true, 1000, 60, 1024 * 1024, UnidentifiedTarballAction.ALLOW);
    private final NpmPackumentIndex npmIndex =
            new NpmPackumentIndex(new JsonMapper(), npmProperties, mock(NpmTarballIndexDao.class));
    private final PackageIdentificationService packageIdentification =
            new PackageIdentificationService(urlParserService, npmIndex, npmProperties);

    private final ProxyController controller = new ProxyController(securityService, auditLogService,
            proxyStreamClient, packageIdentification, npmIndex, meterRegistry, new JsonMapper(),
            new DatabaseAvailabilityService(mock(HealthCheckDao.class), new SimpleMeterRegistry()));

    @BeforeEach
    void unidentifiedUrl() {
        controller.setResponseIdentification(responseIdentification);
        when(urlParserService.parseUrl(anyString())).thenReturn(ParsedPackage.unknown(ParsedPackage.UNKNOWN));
        when(responseIdentification.isEnabled()).thenReturn(true);
    }

    private static byte[] body(int size) {
        byte[] body = new byte[size];
        new Random(7).nextBytes(body);
        return body;
    }

    private static ExpectedDigest sha1Of(byte[] body) throws Exception {
        return new ExpectedDigest(HashType.SHA1, HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(body)));
    }

    private void upstreamServes(byte[] body, ExpectedDigest announced) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Checksum-Sha1", announced.hex());
        headers.setContentLength(body.length);
        when(proxyStreamClient.streamContent(eq(FORWARD_URL), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, headers, new ByteArrayInputStream(body)));
        when(responseIdentification.identify(eq(HttpStatus.OK), any(HttpHeaders.class)))
                .thenReturn(Optional.of(new ResponseIdentification(PKG, announced)));
    }

    private void decision(String result) {
        when(securityService.getDecision("org.example:lib", "1.0.0", "maven", URL))
                .thenReturn(new DecisionResult("BLACKLIST".equals(result) ? "COMPANY_POLICY" : "DEFAULT", result,
                        "reason"));
    }

    private MockMvc mockMvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void shouldBlockPackageIdentifiedFromResponseWithoutRelayingBody() throws Exception {
        byte[] body = body(1000);
        upstreamServes(body, sha1Of(body));
        decision("BLACKLIST");

        mockMvc().perform(get(URL))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.package").value("org.example:lib"))
                .andExpect(jsonPath("$.version").value("1.0.0"))
                .andExpect(jsonPath("$.ecosystem").value("maven"));

        verify(auditLogService).logAudit(eq("org.example:lib"), eq("1.0.0"), eq("maven"), eq("COMPANY_POLICY"),
                eq("BLACKLIST"), anyString(), anyInt(), eq(URL));
        assertThat(meterRegistry.find(Metrics.BYPASS_METRIC).counter()).isNull();
    }

    @Test
    void shouldRelayAllowedPackageIdentifiedFromResponse() throws Exception {
        byte[] body = body(40_000);
        upstreamServes(body, sha1Of(body));
        decision("ALLOW");

        mockMvc().perform(get(URL))
                .andExpect(status().isOk())
                .andExpect(content().bytes(body));

        verify(auditLogService).logAudit(eq("org.example:lib"), eq("1.0.0"), eq("maven"), anyString(),
                eq("ALLOW"), anyString(), anyInt(), eq(URL));
    }

    @Test
    void shouldCutConnectionWhenLargeBodyDoesNotMatchAnnouncedDigest() throws Exception {
        byte[] served = body(40_000);
        upstreamServes(served, sha1Of("the harmless file the upstream pretends to serve".getBytes()));
        decision("ALLOW");
        MockHttpServletRequest request = get(URL).buildRequest(new MockServletContext());
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> controller.proxyRequest(request, response))
                .isInstanceOf(ChecksumMismatchException.class);

        assertThat(response.isCommitted()).isTrue();
        assertThat(response.getContentAsByteArray().length).isLessThan(served.length);
        assertThat(meterRegistry.get(Metrics.CHECKSUM_MISMATCH_METRIC).tag(Metrics.TAG_ECOSYSTEM, "maven")
                .counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldAnswerBadGatewayWhenSmallBodyDoesNotMatchAnnouncedDigest() throws Exception {
        byte[] served = body(1000);
        upstreamServes(served, sha1Of("another file".getBytes()));
        decision("ALLOW");

        mockMvc().perform(get(URL))
                .andExpect(status().isBadGateway())
                .andExpect(content().bytes(new byte[0]));
    }

    @Test
    void shouldRelayUncheckedWhenResponseDoesNotIdentifyPackage() throws Exception {
        byte[] body = body(1000);
        when(proxyStreamClient.streamContent(eq(FORWARD_URL), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream(body)));
        when(responseIdentification.identify(any(), any())).thenReturn(Optional.empty());

        mockMvc().perform(get(URL))
                .andExpect(status().isOk())
                .andExpect(content().bytes(body));

        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
        assertThat(meterRegistry.get(Metrics.BYPASS_METRIC).counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldRelayAsBeforeWhenFeatureIsDisabled() throws Exception {
        byte[] body = body(1000);
        upstreamServes(body, sha1Of(body));
        when(responseIdentification.isEnabled()).thenReturn(false);

        mockMvc().perform(get(URL))
                .andExpect(status().isOk())
                .andExpect(content().bytes(body));

        verify(responseIdentification, never()).identify(any(), any());
        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldNotIdentifyFromResponseWhenServiceIsNotInjected() throws Exception {
        byte[] body = body(1000);
        upstreamServes(body, sha1Of(body));
        ProxyController legacy = new ProxyController(securityService, auditLogService, proxyStreamClient,
                packageIdentification, npmIndex, meterRegistry, new JsonMapper(),
                new DatabaseAvailabilityService(mock(HealthCheckDao.class), new SimpleMeterRegistry()));

        MockMvcBuilders.standaloneSetup(legacy).build().perform(get(URL))
                .andExpect(status().isOk())
                .andExpect(content().bytes(body));

        verify(responseIdentification, never()).identify(any(), any());
        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
    }
}
