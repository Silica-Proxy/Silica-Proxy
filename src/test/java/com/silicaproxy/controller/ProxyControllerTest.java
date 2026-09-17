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
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.dao.npm.NpmTarballIndexDao;
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
import java.util.Optional;

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

    @Mock
    private NpmTarballIndexDao npmTarballIndexDao;

    private final MeterRegistry meterRegistry = new SimpleMeterRegistry();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        ProxyController controller = new ProxyController(securityService, auditLogService, proxyStreamClient, urlParserService, meterRegistry, new JsonMapper(), npmTarballIndexDao);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void shouldStreamValidPackageWithHeaders() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
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

        verify(securityService).getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString());
        verify(proxyStreamClient).streamContent(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"), any(HttpHeaders.class));
        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.21"), eq("npm"), eq("COMPANY_POLICY"), eq("ALLOW"), anyString(), anyInt(), anyString());
    }

    @Test
    void shouldCloseUpstreamResponseAfterForwarding() throws Exception {
        // Regression test: forwardRequest() used to never release the ClientHttpResponse behind
        // streamContent() (StreamUtils.copy() only reads the body, it never closes anything),
        // leaking a connection on every proxied request. The underlying response wrapped in
        // StreamResponse must be closed once forwarding completes.
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));

        byte[] fakeTarball = "fake-tarball-content".getBytes();
        java.io.Closeable underlyingResponse = mock(java.io.Closeable.class);
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeTarball),
                        underlyingResponse
                ));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeTarball));

        verify(underlyingResponse).close();
    }

    @Test
    void shouldBlockPackageAndReturnRfc7807() throws Exception {
        DecisionResult blocked = new DecisionResult("PUBLIC_VULN", "BLOCK", "Known vulnerability CVE-1234");
        when(securityService.getDecision(eq("lodash"), eq("4.17.20"), eq("npm"), anyString())).thenReturn(blocked);
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

        verify(securityService).getDecision(eq("lodash"), eq("4.17.20"), eq("npm"), anyString());
        verifyNoInteractions(proxyStreamClient);
        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.20"), eq("npm"), eq("PUBLIC_VULN"), eq("BLOCK"), anyString(), anyInt(), anyString());
    }

    @Test
    void shouldStripPortWhenUpgradingToHttps() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        
        byte[] fakeTarball = "fake-tarball-content".getBytes();
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeTarball)
                ));

        // We simulate a request where Tomcat's own connector accepted the connection on port 8080
        // (request.getLocalPort()), and that same port leaked into the reconstructed absolute URL
        // -- a connector artifact, not a genuine target port, so it must be stripped.
        mockMvc.perform(get("http://registry.npmjs.org:8080/lodash/-/lodash-4.17.21.tgz")
                        .with(req -> {
                            req.setLocalPort(8080);
                            return req;
                        }))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeTarball));

        verify(proxyStreamClient).streamContent(eq("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"), any(HttpHeaders.class));
    }

    @Test
    void shouldPreserveGenuinePortDistinctFromConnectorPort() throws Exception {
        // Unlike shouldStripPortWhenUpgradingToHttps above, here the absolute URI's port (8081)
        // genuinely differs from the connector's own local port (8080, request.getLocalPort()):
        // it is part of the original request (e.g. a private mirror on a non-standard port) and
        // must be preserved rather than silently dropped (spec bug: previously always stripped).
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));

        byte[] fakeContent = "mirror-content".getBytes();
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK,
                        new HttpHeaders(),
                        new ByteArrayInputStream(fakeContent)
                ));

        mockMvc.perform(get("http://mirror.interne:8081/artifact.jar")
                        .with(req -> {
                            req.setLocalPort(8080);
                            return req;
                        }))
                .andExpect(status().isOk())
                .andExpect(content().bytes(fakeContent));

        verify(proxyStreamClient).streamContent(eq("https://mirror.interne:8081/artifact.jar"), any(HttpHeaders.class));
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
        assertThat(meterRegistry.get(Metrics.BYPASS_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "maven")
                .counter().count()).isEqualTo(1.0);
        verify(proxyStreamClient).streamContent(eq("https://repo1.maven.org/api/system/version"), any(HttpHeaders.class));
    }

    @Test
    void shouldIncrementBypassMetricForFullyUnrecognizedUrl() throws Exception {
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));
        stubStreaming("some-content".getBytes());

        double before = meterRegistry.find(Metrics.BYPASS_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "unknown").counter() == null ? 0.0
                : meterRegistry.get(Metrics.BYPASS_METRIC).tag(Metrics.TAG_ECOSYSTEM, "unknown").counter().count();

        mockMvc.perform(get("http://unknown-host.example/some/random/path"))
                .andExpect(status().isOk());

        verifyNoInteractions(securityService);
        assertThat(meterRegistry.get(Metrics.BYPASS_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "unknown").counter().count() - before).isEqualTo(1.0);
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
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(whitelisted);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        stubStreaming("whitelisted-content".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk());

        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.21"), eq("npm"), eq("COMPANY_POLICY"), eq("WHITELIST"), anyString(), anyInt(), anyString());
    }

    @Test
    void shouldBlockAndReturnRfc7807WhenDecisionIsBlacklist() throws Exception {
        DecisionResult blacklisted = new DecisionResult("COMPANY_POLICY", "BLACKLIST", "Banned by security team");
        when(securityService.getDecision(eq("shelljs"), eq("0.8.5"), eq("npm"), anyString())).thenReturn(blacklisted);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("shelljs", "0.8.5", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/shelljs/-/shelljs-0.8.5.tgz"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("SecurityBlocked"))
                .andExpect(jsonPath("$.step").value("COMPANY_POLICY"))
                .andExpect(jsonPath("$.detail").value("Banned by security team"));

        verifyNoInteractions(proxyStreamClient);
        verify(auditLogService).logAudit(eq("shelljs"), eq("0.8.5"), eq("npm"), eq("COMPANY_POLICY"), eq("BLACKLIST"), anyString(), anyInt(), anyString());
    }

    @Test
    void shouldUseQuarantineBlockedErrorCodeForQuarantineStep() throws Exception {
        DecisionResult quarantined = new DecisionResult("REGISTRY_QUARANTINE", "BLOCK", "Published less than 7 days ago");
        when(securityService.getDecision(eq("new-pkg"), eq("0.0.1"), eq("npm"), anyString())).thenReturn(quarantined);
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
        when(securityService.getDecision(eq("some-pkg"), eq("1.0.0"), eq("npm"), anyString())).thenReturn(blocked);
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
        when(securityService.getDecision(eq("safe-pkg"), eq("1.0.0"), eq("npm"), anyString())).thenReturn(cached);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("safe-pkg", "1.0.0", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/safe-pkg/-/safe-pkg-1.0.0.tgz"))
                .andExpect(status().isOk());
    }

    @Test
    void shouldAllowWhenDecisionIsDefault() throws Exception {
        DecisionResult defaultAllow = new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule).");
        when(securityService.getDecision(eq("unrated-pkg"), eq("1.0.0"), eq("npm"), anyString())).thenReturn(defaultAllow);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unrated-pkg", "1.0.0", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/unrated-pkg/-/unrated-pkg-1.0.0.tgz"))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturnBadGatewayWhenUpstreamRegistryFailsAfterAllow() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenThrow(new IOException("Connection refused"));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isBadGateway());

        // The decision was made and audited even if the upstream relay failed afterwards.
        verify(auditLogService).logAudit(eq("lodash"), eq("4.17.21"), eq("npm"), eq("COMPANY_POLICY"), eq("ALLOW"), anyString(), anyInt(), anyString());
    }

    @Test
    void shouldLogAuditWithExactReasonAndNonNegativeExecutionTime() throws Exception {
        DecisionResult blocked = new DecisionResult("PUBLIC_VULN", "BLOCK", "Known vulnerability CVE-9999");
        when(securityService.getDecision(eq("vuln-pkg"), eq("1.0.0"), eq("npm"), anyString())).thenReturn(blocked);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("vuln-pkg", "1.0.0", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/vuln-pkg/-/vuln-pkg-1.0.0.tgz"))
                .andExpect(status().isForbidden());

        ArgumentCaptor<String> reasonCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> executionTimeCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(auditLogService).logAudit(
                eq("vuln-pkg"), eq("1.0.0"), eq("npm"), eq("PUBLIC_VULN"), eq("BLOCK"),
                reasonCaptor.capture(), executionTimeCaptor.capture(), anyString());

        assertThat(reasonCaptor.getValue()).isEqualTo("Known vulnerability CVE-9999");
        assertThat(executionTimeCaptor.getValue()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void shouldPropagateMultipleRequestHeadersToUpstreamOnAllow() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
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
    void shouldIncrementDecisionCounterTaggedByVerdictSourceAndEcosystemOnAllow() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk());

        assertThat(meterRegistry.get(Metrics.DECISIONS_METRIC)
                .tag(Metrics.TAG_VERDICT, "ALLOW")
                .tag(Metrics.TAG_SOURCE, "COMPANY_POLICY")
                .tag(Metrics.TAG_ECOSYSTEM, "npm")
                .counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldIncrementDecisionCounterTaggedByVerdictSourceAndEcosystemOnBlock() throws Exception {
        DecisionResult blocked = new DecisionResult("PUBLIC_VULN", "BLOCK", "Known vulnerability CVE-1234");
        when(securityService.getDecision(eq("lodash"), eq("4.17.20"), eq("npm"), anyString())).thenReturn(blocked);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.20", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"))
                .andExpect(status().isForbidden());

        assertThat(meterRegistry.get(Metrics.DECISIONS_METRIC)
                .tag(Metrics.TAG_VERDICT, "BLOCK")
                .tag(Metrics.TAG_SOURCE, "PUBLIC_VULN")
                .tag(Metrics.TAG_ECOSYSTEM, "npm")
                .counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldIncrementDecisionCounterForWhitelistAndBlacklistVerdicts() throws Exception {
        DecisionResult whitelisted = new DecisionResult("COMPANY_POLICY", "WHITELIST", "Approved by security team");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(whitelisted);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("lodash", "4.17.21", "npm"));
        stubStreaming("whitelisted-content".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"))
                .andExpect(status().isOk());

        DecisionResult blacklisted = new DecisionResult("COMPANY_POLICY", "BLACKLIST", "Banned by security team");
        when(securityService.getDecision(eq("shelljs"), eq("0.8.5"), eq("npm"), anyString())).thenReturn(blacklisted);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("shelljs", "0.8.5", "npm"));

        mockMvc.perform(get("http://registry.npmjs.org/shelljs/-/shelljs-0.8.5.tgz"))
                .andExpect(status().isForbidden());

        assertThat(meterRegistry.get(Metrics.DECISIONS_METRIC)
                .tag(Metrics.TAG_VERDICT, "WHITELIST").tag(Metrics.TAG_SOURCE, "COMPANY_POLICY").tag(Metrics.TAG_ECOSYSTEM, "npm")
                .counter().count()).isEqualTo(1.0);
        assertThat(meterRegistry.get(Metrics.DECISIONS_METRIC)
                .tag(Metrics.TAG_VERDICT, "BLACKLIST").tag(Metrics.TAG_SOURCE, "COMPANY_POLICY").tag(Metrics.TAG_ECOSYSTEM, "npm")
                .counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldAccumulateDecisionCounterAcrossRepeatedRequestsForSameTags() throws Exception {
        DecisionResult allowed = new DecisionResult("DEFAULT", "ALLOW", "Allowed by default (no blocking rule).");
        when(securityService.getDecision(eq("unrated-pkg"), eq("1.0.0"), eq("npm"), anyString())).thenReturn(allowed);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unrated-pkg", "1.0.0", "npm"));
        stubStreaming("ok".getBytes());

        mockMvc.perform(get("http://registry.npmjs.org/unrated-pkg/-/unrated-pkg-1.0.0.tgz")).andExpect(status().isOk());
        mockMvc.perform(get("http://registry.npmjs.org/unrated-pkg/-/unrated-pkg-1.0.0.tgz")).andExpect(status().isOk());
        mockMvc.perform(get("http://registry.npmjs.org/unrated-pkg/-/unrated-pkg-1.0.0.tgz")).andExpect(status().isOk());

        assertThat(meterRegistry.get(Metrics.DECISIONS_METRIC)
                .tag(Metrics.TAG_VERDICT, "ALLOW")
                .tag(Metrics.TAG_SOURCE, "DEFAULT")
                .tag(Metrics.TAG_ECOSYSTEM, "npm")
                .counter().count()).isEqualTo(3.0);
    }

    @Test
    void shouldForwardQueryStringToUpstreamUrl() throws Exception {
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
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
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
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
        when(securityService.getDecision(eq("lodash"), eq("4.17.21"), eq("npm"), anyString())).thenReturn(allowed);
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

    @Test
    void shouldTagBypassWithNpmWhenMetadataDetectorRecognisesUnknownHost() throws Exception {
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class)))
                .thenReturn(Optional.of(new UrlParserService.ParsedPackage("@jsr/zerun__group-deps", "unknown", "npm")));
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, new HttpHeaders(), new ByteArrayInputStream("{}".getBytes())));

        mockMvc.perform(get("http://npm.jsr.io/@jsr/zerun__group-deps")
                        .header("Accept", "application/vnd.npm.install-v1+json"))
                .andExpect(status().isOk());

        verify(urlParserService).detectNpmMetadata(eq("http://npm.jsr.io/@jsr/zerun__group-deps"), any(HttpHeaders.class));
        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
        verify(proxyStreamClient).streamContent(eq("https://npm.jsr.io/@jsr/zerun__group-deps"), any(HttpHeaders.class));
        assertThat(meterRegistry.get(Metrics.BYPASS_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, "npm").counter().count()).isEqualTo(1.0);
    }

    @Test
    void shouldIdentifyTarballFromRelayedPackumentWhateverTheUrlLayout() throws Exception {
        // 1. Packument on an unknown host : bypassed, but its dist.tarball URLs get indexed.
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class)))
                .thenReturn(Optional.of(new UrlParserService.ParsedPackage("@jsr/zerun__group-deps", "unknown", "npm")));
        String packument = """
                {"name":"@jsr/zerun__group-deps","versions":{"0.1.5":{"version":"0.1.5",
                 "dist":{"tarball":"https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz"}}}}
                """;
        HttpHeaders jsonHeaders = new HttpHeaders();
        jsonHeaders.add("Content-Type", "application/vnd.npm.install-v1+json");
        when(proxyStreamClient.streamContent(eq("https://npm.jsr.io/@jsr/zerun__group-deps"), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, jsonHeaders,
                        new ByteArrayInputStream(packument.getBytes())));

        mockMvc.perform(get("http://npm.jsr.io/@jsr/zerun__group-deps"))
                .andExpect(status().isOk())
                .andExpect(content().string(packument));
        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());

        // 2. Tarball with the JSR layout : the parser still cannot name a version, the index can.
        DecisionResult allowed = new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test");
        when(securityService.getDecision(eq("@jsr/zerun__group-deps"), eq("0.1.5"), eq("npm"), anyString())).thenReturn(allowed);
        byte[] tarball = "fake-tarball".getBytes();
        when(proxyStreamClient.streamContent(eq("https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz"), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, new HttpHeaders(), new ByteArrayInputStream(tarball)));

        mockMvc.perform(get("http://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(tarball));

        verify(securityService).getDecision(eq("@jsr/zerun__group-deps"), eq("0.1.5"), eq("npm"), anyString());
        verify(auditLogService).logAudit(eq("@jsr/zerun__group-deps"), eq("0.1.5"), eq("npm"), eq("COMPANY_POLICY"), eq("ALLOW"),
                anyString(), anyInt(), anyString());
    }

    @Test
    void shouldBlockTarballIdentifiedThroughPackumentIndex() throws Exception {
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class)))
                .thenReturn(Optional.of(new UrlParserService.ParsedPackage("unknown", "unknown", "npm")));
        HttpHeaders jsonHeaders = new HttpHeaders();
        jsonHeaders.add("Content-Type", "application/json; charset=utf-8");
        String packument = "{\"name\":\"evil\",\"versions\":{\"1.0.0\":{\"dist\":{\"tarball\":\"https://mirror.internal/blobs/abc.tgz\"}}}}";
        when(proxyStreamClient.streamContent(eq("https://mirror.internal/evil"), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, jsonHeaders, new ByteArrayInputStream(packument.getBytes())));
        mockMvc.perform(get("http://mirror.internal/evil")).andExpect(status().isOk());

        when(securityService.getDecision(eq("evil"), eq("1.0.0"), eq("npm"), anyString()))
                .thenReturn(new DecisionResult("BLACKLIST", "BLOCK", "Known malware"));

        mockMvc.perform(get("http://mirror.internal/blobs/abc.tgz"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.package").value("evil"))
                .andExpect(jsonPath("$.version").value("1.0.0"));
        verify(proxyStreamClient, never()).streamContent(eq("https://mirror.internal/blobs/abc.tgz"), any(HttpHeaders.class));
    }

    @Test
    void shouldNotIndexNonJsonOrNonOkMetadataResponses() throws Exception {
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "npm"));
        HttpHeaders html = new HttpHeaders();
        html.add("Content-Type", "text/html");
        String body = "{\"name\":\"x\",\"versions\":{\"1.0.0\":{\"dist\":{\"tarball\":\"https://r.internal/x.tgz\"}}}}";
        when(proxyStreamClient.streamContent(eq("https://r.internal/x"), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, html, new ByteArrayInputStream(body.getBytes())));
        HttpHeaders json = new HttpHeaders();
        json.add("Content-Type", "application/json");
        when(proxyStreamClient.streamContent(eq("https://r.internal/y"), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.NOT_FOUND, json, new ByteArrayInputStream(body.getBytes())));
        when(proxyStreamClient.streamContent(eq("https://r.internal/x.tgz"), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, new HttpHeaders(), new ByteArrayInputStream(new byte[0])));

        mockMvc.perform(get("http://r.internal/x")).andExpect(status().isOk()).andExpect(content().string(body));
        mockMvc.perform(get("http://r.internal/y")).andExpect(status().isNotFound());
        mockMvc.perform(get("http://r.internal/x.tgz")).andExpect(status().isOk());

        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
    }
}
