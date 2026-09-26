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

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.client.DepsDevClient;
import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.service.decision.SecurityService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@code response-identification.enabled=false} : a download the URL does not identify is relayed
 * unchecked, as before the feature — no file_digest_index read, no deps.dev call.
 */
@TestPropertySource(properties = {
        "silicaproxy.response-identification.enabled=false",
        "silicaproxy.api-fallback.deps-dev.enabled=true"
})
class ProxyControllerResponseIdentificationDisabledIntegrationTest extends BaseIntegrationTest {

    private static final String URL = "http://repo.corp.example/api/download/blob/4f2a91";

    @LocalServerPort
    private int port;

    @MockitoBean
    private ProxyStreamClient proxyStreamClient;

    @MockitoBean
    private SecurityService securityService;

    @MockitoSpyBean
    private DepsDevClient depsDevClient;

    @Autowired
    private JdbcClient jdbcClient;

    @Test
    void shouldRelayUncheckedWithoutAnyLookup() throws Exception {
        jdbcClient.sql("TRUNCATE file_digest_index").update();
        byte[] body = "internal-lib.jar bytes".getBytes();
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Checksum-Sha1", "7cf2726fdcfbc8610f9a71fb3ed639871f315340");
        when(proxyStreamClient.streamContent(anyString(), any(HttpHeaders.class)))
                .thenReturn(new ProxyStreamClient.StreamResponse(HttpStatus.OK, headers, new ByteArrayInputStream(body)));
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)));

        byte[] relayed = RestClient.builder().requestFactory(factory).build()
                .get().uri(URL).retrieve().body(byte[].class);

        assertThat(relayed).isEqualTo(body);
        verify(depsDevClient, never()).queryByHash(any(), anyString());
        verify(securityService, never()).getDecision(anyString(), anyString(), anyString(), anyString());
        assertThat(jdbcClient.sql("SELECT COUNT(*) FROM file_digest_index").query(Integer.class).single()).isZero();
    }
}
