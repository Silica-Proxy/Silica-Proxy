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
import com.silicaproxy.service.interception.HttpsUpgradePolicy;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import com.silicaproxy.service.interception.PackageIdentificationService;
import com.silicaproxy.service.interception.PackageIdentificationService.Identification;
import com.silicaproxy.service.interception.PackageIdentificationService.Outcome;
import com.silicaproxy.service.interception.ParsedPackage;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** The security decision must see the same https:// URL the proxy relays upstream (Cloudflare 403 on plain HTTP). */
class ProxyControllerHttpsUpgradeTest {

    private static final String POM_PATH = "/m2/com/acme/lib/1.0/lib-1.0.pom";

    @Mock
    private SecurityService securityService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private ProxyStreamClient proxyStreamClient;

    @Mock
    private PackageIdentificationService packageIdentification;

    @Mock
    private NpmPackumentIndex npmPackumentIndex;

    private ProxyController controller;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        controller = new ProxyController(securityService, auditLogService, proxyStreamClient,
                packageIdentification, npmPackumentIndex, new SimpleMeterRegistry(), new JsonMapper());
        when(packageIdentification.identify(anyString(), anyString(), any(HttpHeaders.class)))
                .thenReturn(new Identification(new ParsedPackage("com.acme:lib", "1.0", "maven"), Outcome.EVALUATE, false));
        when(securityService.getDecision(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new DecisionResult("COMPANY_POLICY", "ALLOW", "Allowed by test"));
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(
                        HttpStatus.OK, new HttpHeaders(), new ByteArrayInputStream(new byte[0])));
    }

    private MockMvc mockMvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void securityDecisionReceivesTheHttpsUrlByDefault() throws Exception {
        mockMvc().perform(get("http://plugins.gradle.org" + POM_PATH));

        verify(securityService).getDecision(eq("com.acme:lib"), eq("1.0"), eq("maven"),
                eq("https://plugins.gradle.org" + POM_PATH));
        verify(proxyStreamClient).streamContent(eq("https://plugins.gradle.org" + POM_PATH), any(HttpHeaders.class));
    }

    @Test
    void httpOnlyHostKeepsItsHttpUrlForDecisionAndRelay() throws Exception {
        controller.setHttpsUpgradePolicy(HttpsUpgradePolicy.fromCsv("plugins.gradle.org"));

        mockMvc().perform(get("http://plugins.gradle.org" + POM_PATH));

        verify(securityService).getDecision(eq("com.acme:lib"), eq("1.0"), eq("maven"),
                eq("http://plugins.gradle.org" + POM_PATH));
        verify(proxyStreamClient).streamContent(eq("http://plugins.gradle.org" + POM_PATH), any(HttpHeaders.class));
    }

    @Test
    void otherHostsAreStillUpgradedWhenAnotherHostIsHttpOnly() throws Exception {
        controller.setHttpsUpgradePolicy(HttpsUpgradePolicy.fromCsv("internal.registry"));

        mockMvc().perform(get("http://repo1.maven.org" + POM_PATH));

        verify(securityService).getDecision(eq("com.acme:lib"), eq("1.0"), eq("maven"),
                eq("https://repo1.maven.org" + POM_PATH));
    }
}
