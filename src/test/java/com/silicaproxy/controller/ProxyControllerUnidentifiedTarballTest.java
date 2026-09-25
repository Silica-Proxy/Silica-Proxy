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
import com.silicaproxy.dao.npm.NpmTarballIndexDao;
import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import com.silicaproxy.service.interception.UrlParserService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An npm tarball identified neither by its URL nor by a relayed packument is relayed unchecked by
 * default, and answered 403 {@code UNIDENTIFIED_ARTIFACT} with
 * {@code npm-packument-index.unidentified-tarball-action=BLOCK}.
 */
class ProxyControllerUnidentifiedTarballTest {

    private static final String TARBALL_URL = "http://registry.corp.example/pool/abc/internal-lib.tgz";

    private final SecurityService securityService = mock(SecurityService.class);
    private final AuditLogService auditLogService = mock(AuditLogService.class);
    private final ProxyStreamClient proxyStreamClient = mock(ProxyStreamClient.class);
    private final UrlParserService urlParserService = mock(UrlParserService.class);

    private MockMvc mockMvc(UnidentifiedTarballAction action) throws Exception {
        NpmPackumentIndex index = new NpmPackumentIndex(new JsonMapper(),
                new NpmPackumentIndexProperties(true, 1000, 60, 1024 * 1024, action), mock(NpmTarballIndexDao.class));
        ProxyController controller = new ProxyController(securityService, auditLogService, proxyStreamClient,
                urlParserService, new SimpleMeterRegistry(), new JsonMapper(), index);
        when(urlParserService.parseUrl(anyString())).thenReturn(new UrlParserService.ParsedPackage("unknown", "unknown", "unknown"));
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class)))
                .thenReturn(Optional.of(new UrlParserService.ParsedPackage("unknown", "unknown", "npm")));
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, new HttpHeaders(),
                        new ByteArrayInputStream("tarball".getBytes())));
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void shouldBlockUnidentifiedNpmTarballWhenConfigured() throws Exception {
        mockMvc(UnidentifiedTarballAction.BLOCK).perform(get(TARBALL_URL).header("User-Agent", "npm/10.5.0"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.step").value("UNIDENTIFIED_ARTIFACT"));

        verify(proxyStreamClient, never()).streamContent(anyString(), any(HttpHeaders.class));
        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
        verify(auditLogService).logAudit(anyString(), anyString(), eq("npm"), eq("UNIDENTIFIED_ARTIFACT"),
                eq("BLOCK"), anyString(), anyInt(), anyString());
    }

    @Test
    void shouldRelayUnidentifiedNpmTarballByDefault() throws Exception {
        mockMvc(UnidentifiedTarballAction.ALLOW).perform(get(TARBALL_URL).header("User-Agent", "npm/10.5.0"))
                .andExpect(status().isOk());

        verify(proxyStreamClient).streamContent(eq("https://registry.corp.example/pool/abc/internal-lib.tgz"),
                any(HttpHeaders.class));
    }

    @Test
    void shouldStillRelayNpmMetadataWhenBlockingTarballs() throws Exception {
        mockMvc(UnidentifiedTarballAction.BLOCK).perform(get("http://registry.corp.example/internal-lib")
                        .header("User-Agent", "npm/10.5.0"))
                .andExpect(status().isOk());

        verify(proxyStreamClient).streamContent(eq("https://registry.corp.example/internal-lib"), any(HttpHeaders.class));
    }
}
