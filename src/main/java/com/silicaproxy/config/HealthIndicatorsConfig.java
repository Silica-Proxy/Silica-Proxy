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


package com.silicaproxy.config;

import com.silicaproxy.service.monitoring.MonitoringService;
import com.silicaproxy.service.monitoring.MonitoringService.ComponentHealth;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes the same per-component checks already computed by {@link MonitoringService} for
 * {@code GET /api/monitoring/health} as standard Spring Boot {@link HealthIndicator} beans, so
 * they also appear under {@code GET /actuator/health} (component keys: {@code database},
 * {@code vulnerabilitySync}, {@code gitopsSync}, {@code osvIncrementalSync}). No check logic is
 * duplicated here -- each bean only adapts {@link ComponentHealth} to {@link Health}.
 */
@Configuration
@NullMarked
public class HealthIndicatorsConfig {

    private static final Status DEGRADED = new Status("DEGRADED");

    private static Health toHealth(ComponentHealth componentHealth) {
        Health.Builder builder = switch (componentHealth.status()) {
            case "UP" -> Health.up();
            case "DOWN" -> Health.down();
            default -> Health.status(DEGRADED);
        };
        return builder.withDetails(componentHealth.details()).build();
    }

    @Bean
    public HealthIndicator databaseHealthIndicator(MonitoringService monitoringService) {
        return () -> toHealth(monitoringService.databaseHealth());
    }

    @Bean
    public HealthIndicator vulnerabilitySyncHealthIndicator(MonitoringService monitoringService) {
        return () -> toHealth(monitoringService.vulnerabilitySyncHealth());
    }

    @Bean
    public HealthIndicator gitopsSyncHealthIndicator(MonitoringService monitoringService) {
        return () -> toHealth(monitoringService.gitopsSyncHealth());
    }

    @Bean
    public HealthIndicator osvIncrementalSyncHealthIndicator(MonitoringService monitoringService) {
        return () -> toHealth(monitoringService.osvIncrementalSyncHealth());
    }
}
