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

import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.UrlParserService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ProxyControllerTest {

    private MockMvc mockMvc;

    @Mock
    private SecurityService securityService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private ProxyStreamClient proxyStreamClient;

    @Mock
    private UrlParserService urlParserService;

    private final MeterRegistry meterRegistry = new SimpleMeterRegistry();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        ProxyController controller = new ProxyController(securityService, auditLogService, proxyStreamClient, urlParserService, meterRegistry, new JsonMapper());
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void shouldStreamValidPackageWithHeaders() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        
        byte[] fakeTarball = "fake-tarball-content".getBytes();
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeTarball)
                ));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                        .header("Authorization", "Bearer secret-token"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeTarball));

        verify(securityService).getDecision("lodash", "4.17.21", "npm");
        verify(proxyStreamClient).streamContent(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"), any(HttpHeaders.class));
        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.21"), eq("npm"), eq("COMPANY_POLICY"), eq("ALLOW"), anyString(), anyInt());
    }

    @Test
    void shouldBlockPackageAndReturnRfc7807() throws Exception {
        DecisionResult blocked = new DecisionResult("PUBLIC_VULN", "BLOCK", "Known vulnerability CVE-1234");
        when(securityService.getDecision("lodash", "4.17.20", "npm")).thenReturn(blocked);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.20", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"))
                .andExpect(status().isForbidden())
                .andExpect(header().string("Content-Type", "application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.title").value("Forbidden"))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.detail").value("Known vulnerability CVE-1234"))
                .andExpect(jsonPath("$.step").value("PUBLIC_VULN"))
                .andExpect(jsonPath("$.package").value("lodash"))
                .andExpect(jsonPath("$.version").value("4.17.20"))
                .andExpect(jsonPath("$.ecosystem").value("npm"));

        verify(securityService).getDecision("lodash", "4.17.20", "npm");
        verifyNoInteractions(proxyStreamClient);
        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.20"), eq("npm"), eq("PUBLIC_VULN"), eq("BLOCK"), anyString(), anyInt());
    }

    @Test
    void shouldStripPortWhenUpgradingToHttps() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        
        byte[] fakeTarball = "fake-tarball-content".getBytes();
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeTarball)
                ));

        // We simulate a request where Tomcat appended the connector port (e.g., 8080) to the reconstructed URL
        mockMvc.perform(get("http://registry.npmjs.org:8080/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeTarball));

        verify(proxyStreamClient).streamContent(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"), any(HttpHeaders.class));
    }

    @Test
    void shouldNotUpgradeOrStripPortForLocalhost() throws Exception {
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));
        
        byte[] fakeContent = "local-content".getBytes();
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeContent)
                ));

        mockMvc.perform(get("http://localhost:8080/npm/lodash"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeContent));

        verify(proxyStreamClient).streamContent(eq("http://localhost:8080/npm/lodash"), any(HttpHeaders.class));
    }

    @Test
    void shouldBypassSecurityCheckForUnknownPackages() throws Exception {
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "maven"));

        byte[] fakeContent = "system-version-info".getBytes();
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeContent)
                ));

        mockMvc.perform(get("http://repo1.maven.org/api/system/version"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeContent));

        verifyNoInteractions(securityService);
        verify(proxyStreamClient).streamContent(eq("https://repo1.maven.org/api/system/version"), any(HttpHeaders.class));
    }

    private void stubStreaming(byte[] content) throws Exception {
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(content)
                ));
    }

    @Test
    void shouldStreamWhenDecisionIsWhitelist() throws Exception {
        DecisionResult whitelisted = new DecisionResult("COMPANY_POLICY", "WHITELIST", "Approved by security team");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(whitelisted);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        stubStreaming("whitelisted-content".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk());

        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.21"), eq("npm"), eq("COMPANY_POLICY"), eq("WHITELIST"), anyString(), anyInt());
    }

    @Test
    void shouldBlockAndReturnRfc7807WhenDecisionIsBlacklist() throws Exception {
        DecisionResult blacklisted = new DecisionResult("COMPANY_POLICY", "BLACKLIST", "Banned by security team");
        when(securityService.getDecision("shelljs", "0.8.5", "npm")).thenReturn(blacklisted);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("shelljs", "0.8.5", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/shelljs/-/shelljs-0.8.5.tgz"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("SecurityBlocked"))
                .andExpect(jsonPath("$.step").value("COMPANY_POLICY"))
                .andExpect(jsonPath("$.detail").value("Banned by security team"));

        verifyNoInteractions(proxyStreamClient);
        verify(auditLogService).logAudit(eq("shelljs"), eq("0.8.5"), eq("npm"), eq("COMPANY_POLICY"), eq("BLACKLIST"), anyString(), anyInt());
    }

    @Test
    void shouldUseQuarantineBlockedErrorCodeForQuarantineStep() throws Exception {
        DecisionResult quarantined = new DecisionResult("REGISTRY_QUARANTINE", "BLOCK", "Published less than 7 days ago");
        when(securityService.getDecision("new-pkg", "0.0.1", "npm")).thenReturn(quarantined);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("new-pkg", "0.0.1", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/new-pkg/-/new-pkg-0.0.1.tgz"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("QuarantineBlocked"))
                .andExpect(jsonPath("$.step").value("REGISTRY_QUARANTINE"))
                .andExpect(jsonPath("$.type").value("about:blank"))
                .andExpect(jsonPath("$.title").value("Forbidden"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"COMPANY_POLICY", "PUBLIC_VULN", "REGISTRY_DEPRECATION", "OSV_LIVE", "PHYLUM", "DEPS_DEV", "SONATYPE_OSS", "API_CACHE"})
    void shouldUseSecurityBlockedErrorCodeForEveryNonQuarantineBlockingStep(String sourceType) throws Exception {
        DecisionResult blocked = new DecisionResult(sourceType, "BLOCK", "Blocked for test reasons");
        when(securityService.getDecision("some-pkg", "1.0.0", "npm")).thenReturn(blocked);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("some-pkg", "1.0.0", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/some-pkg/-/some-pkg-1.0.0.tgz"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("SecurityBlocked"))
                .andExpect(jsonPath("$.step").value(sourceType));

        verifyNoInteractions(proxyStreamClient);
    }

    @Test
    void shouldAllowWhenApiCacheDecisionIsAllow() throws Exception {
        DecisionResult cached = new DecisionResult("API_CACHE", "ALLOW", "Validated via API cache");
        when(securityService.getDecision("safe-pkg", "1.0.0", "npm")).thenReturn(cached);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("safe-pkg", "1.0.0", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/safe-pkg/-/safe-pkg-1.0.0.tgz"))
                .andExpect(status().isOk());
    }

    @Test
    void shouldAllowWhenDecisionIsDefault() throws Exception {
        DecisionResult defaultAllow = new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule).");
        when(securityService.getDecision("unrated-pkg", "1.0.0", "npm")).thenReturn(defaultAllow);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unrated-pkg", "1.0.0", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/unrated-pkg/-/unrated-pkg-1.0.0.tgz"))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturnBadGatewayWhenUpstreamRegistryFailsAfterAllow() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenThrow(new IOException("Connection refused"));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isBadGateway());

        // The decision was made and audited even if the upstream relay failed afterwards.
        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.21"), eq("npm"), eq("COMPANY_POLICY"), eq("ALLOW"), anyString(), anyInt());
    }

    @Test
    void shouldLogAuditWithExactReasonAndNonNegativeExecutionTime() throws Exception {
        DecisionResult blocked = new DecisionResult("PUBLIC_VULN", "BLOCK", "Known vulnerability CVE-9999");
        when(securityService.getDecision("vuln-pkg", "1.0.0", "npm")).thenReturn(blocked);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("vuln-pkg", "1.0.0", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/vuln-pkg/-/vuln-pkg-1.0.0.tgz"))
                .andExpect(status().isForbidden());

        ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> executionTimeCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(auditLogService).logAudit(
                eq("vuln-pkg"), eq("1.0.0"), eq("npm"), eq("PUBLIC_VULN"), eq("BLOCK"),
                reasonCaptor.capture(), executionTimeCaptor.capture());

        assertThat(reasonCaptor.getValue()).isEqualTo("Known vulnerability CVE-9999");
        assertThat(executionTimeCaptor.getValue()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void shouldPropagateMultipleRequestHeadersToUpstreamOnAllow() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
                        .header("Authorization", "Bearer secret-token")
                        .header("X-NPM-Auth", "npm-token-value"))
                .andExpect(status().isOk());

        ArgumentCaptor<HttpHeaders> headersCaptor = ArgumentCaptor.forClass(HttpHeaders.class);
        verify(proxyStreamClient).streamContent(anyString(), headersCaptor.capture());

        HttpHeaders forwarded = headersCaptor.getValue();
        assertThat(forwarded.getFirst("Authorization")).isEqualTo("Bearer secret-token");
        assertThat(forwarded.getFirst("X-NPM-Auth")).isEqualTo("npm-token-value");
    }

    @Test
    void shouldForwardQueryStringToUpstreamUrl() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz?cache=false"))
                .andExpect(status().isOk());

        verify(proxyStreamClient).streamContent(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz?cache=false"), any(HttpHeaders.class));
    }

    // JdkClientHttpRequestFactory (Java HttpClient) exposes HTTP/2 pseudo-headers (ex: ":status: 200")
    // in the response map. The ProxyController must filter them before transmitting to the downstream
    // HTTP/1.1 client, for which Apache HttpClient rejects any header starting with ":" with
    // "Invalid header: :status: 200" and marks the remote repository as offline.

    @Test
    void shouldNotForwardHttp2PseudoHeadersToDownstreamClient() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));

        HttpHeaders upstreamHeaders = new HttpHeaders();
        upstreamHeaders.add(":status", "200");
        upstreamHeaders.add(":path", "/lodash/-/lodash-4.17.21.tgz");
        upstreamHeaders.add(":scheme", "https");
        upstreamHeaders.add("Content-Type", "application/octet-stream");
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, upstreamHeaders,
                        new ByteArrayInputStream("data".getBytes())));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist(":status"))
                .andExpect(header().doesNotExist(":path"))
                .andExpect(header().doesNotExist(":scheme"))
                .andExpect(header().string("Content-Type", "application/octet-stream"));
    }

    @Test
    void shouldForwardNormalHeadersWhenUpstreamAlsoSendsPseudoHeaders() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed");
        when(securityService.getDecision("lodash", "4.17.21", "npm")).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));

        HttpHeaders upstreamHeaders = new HttpHeaders();
        upstreamHeaders.add(":status", "200");
        upstreamHeaders.add("Cache-Control", "max-age=3600");
        upstreamHeaders.add("ETag", "\"abc123\"");
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, upstreamHeaders,
                        new ByteArrayInputStream(new byte[0])));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "max-age=3600"))
                .andExpect(header().string("ETag", "\"abc123\""))
                .andExpect(header().doesNotExist(":status"));
    }

}

