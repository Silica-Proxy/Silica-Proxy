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

import com.silicaproxy.service.monitoring.MonitoringService;
import com.silicaproxy.service.monitoring.MonitoringService.ComponentHealth;
import com.silicaproxy.service.monitoring.MonitoringService.HealthReport;
import com.silicaproxy.service.interception.SslMitmService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class MonitoringControllerTest {

    private MockMvc mockMvc;

    @Mock
    private MonitoringService monitoringService;

    @Mock
    private SslMitmService sslMitmService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        MonitoringController controller = new MonitoringController(monitoringService, sslMitmService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void shouldReturnCaCertAsPem() throws Exception {
        String fakePem = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq\n-----END CERTIFICATE-----\n";
        when(sslMitmService.getCaCertPem()).thenReturn(fakePem);

        mockMvc.perform(get("/api/monitoring/ca-cert"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/plain"))
                .andExpect(content().string(fakePem));
    }

    @Test
    void shouldReturnHealthReportCorrectly() throws Exception {
        Map<String, ComponentHealth> mockComponents = Map.of(
                "database", new ComponentHealth("UP", Map.of("message", "Database connection OK", "activeConnections", 5)),
                "vulnerabilitySync", new ComponentHealth("DEGRADED", Map.of("osv-npm", "SUCCESS", "gitlab", "FAILED")),
                "gitopsSync", new ComponentHealth("UP", Map.of("status", "SUCCESS"))
        );

        when(monitoringService.checkHealth()).thenReturn(new HealthReport("DEGRADED", mockComponents));

        mockMvc.perform(get("/api/monitoring/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEGRADED"))
                .andExpect(jsonPath("$.components.database.status").value("UP"))
                .andExpect(jsonPath("$.components.database.details.activeConnections").value(5))
                .andExpect(jsonPath("$.components.vulnerabilitySync.status").value("DEGRADED"))
                .andExpect(jsonPath("$.components.gitopsSync.status").value("UP"));
    }
}
