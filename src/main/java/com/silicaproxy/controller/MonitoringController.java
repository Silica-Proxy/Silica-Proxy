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

import com.silicaproxy.config.ApiKeyScope;
import com.silicaproxy.config.RequiresApiKey;
import com.silicaproxy.service.monitoring.MonitoringService;
import com.silicaproxy.service.interception.SslMitmService;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/monitoring")
@NullMarked
public class MonitoringController {

    private static final Logger LOG = LoggerFactory.getLogger(MonitoringController.class);

    private final MonitoringService monitoringService;
    private final SslMitmService sslMitmService;

    public MonitoringController(MonitoringService monitoringService, SslMitmService sslMitmService) {
        this.monitoringService = monitoringService;
        this.sslMitmService = sslMitmService;
    }

    @GetMapping("/health")
    public MonitoringService.HealthReport getHealth() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Proxy health status evaluation request (health check).");
        }
        return monitoringService.checkHealth();
    }

    @RequiresApiKey(ApiKeyScope.READ)
    @GetMapping(value = "/ca-cert", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getCaCert() {
        return sslMitmService.getCaCertPem();
    }
}
