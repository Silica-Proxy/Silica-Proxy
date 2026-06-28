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


package com.silicaproxy.service.monitoring;

import com.zaxxer.hikari.HikariDataSource;
import com.silicaproxy.dao.sync.HealthCheckDao;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncScheduler;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService.JobStatus;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Aggregates the global health status of the proxy (DB, vulnerabilities sync, GitOps sync) into a
 * UP/DOWN/DEGRADED status. Called only by {@code MonitoringController}, on demand, via
 * {@code GET /api/monitoring/health} .
 */
@Service
@NullMarked
public class MonitoringService {

    private final HealthCheckDao healthCheckDao;
    private final VulnerabilitySyncStatusService statusService;
    private final SilicaProxyProperties properties;
    @Nullable
    private final HikariDataSource dataSource;

    public MonitoringService(
            HealthCheckDao healthCheckDao,
            VulnerabilitySyncStatusService statusService,
            SilicaProxyProperties properties,
            @Nullable HikariDataSource dataSource) {
        this.healthCheckDao = healthCheckDao;
        this.statusService = statusService;
        this.properties = properties;
        this.dataSource = dataSource;
    }

    public record ComponentHealth(
            String status, // UP, DOWN, DEGRADED
            Map<String, Object> details
    ) {
        public ComponentHealth {
            details = Collections.unmodifiableMap(new HashMap<>(details));
        }
    }

    public record HealthReport(
            String status, // UP, DOWN, DEGRADED
            Map<String, ComponentHealth> components
    ) {
        public HealthReport {
            components = Collections.unmodifiableMap(new HashMap<>(components));
        }
    }

    public HealthReport checkHealth() {
        Map<String, ComponentHealth> components = new HashMap<>();
        String overallStatus = "UP";

        ComponentHealth dbHealth = checkDatabaseHealth();
        components.put("database", dbHealth);
        if ("DOWN".equals(dbHealth.status())) {
            overallStatus = "DOWN";
        }

        ComponentHealth vulnHealth = checkVulnerabilitySyncHealth();
        components.put("vulnerabilitySync", vulnHealth);
        if ("DOWN".equals(vulnHealth.status()) && !"DOWN".equals(overallStatus)) {
            overallStatus = "DOWN";
        } else if ("DEGRADED".equals(vulnHealth.status()) && "UP".equals(overallStatus)) {
            overallStatus = "DEGRADED";
        }

        ComponentHealth gitopsHealth = checkGitOpsSyncHealth();
        components.put("gitopsSync", gitopsHealth);
        if ("DOWN".equals(gitopsHealth.status()) && !"DOWN".equals(overallStatus)) {
            overallStatus = "DOWN";
        } else if ("DEGRADED".equals(gitopsHealth.status()) && "UP".equals(overallStatus)) {
            overallStatus = "DEGRADED";
        }

        return new HealthReport(overallStatus, components);
    }

    private ComponentHealth checkDatabaseHealth() {
        Map<String, Object> details = new HashMap<>();
        try {
            healthCheckDao.isDatabaseReachable();
            details.put("message", "Database connection OK");
            
            if (dataSource != null && dataSource.getHikariPoolMXBean() != null) {
                details.put("activeConnections", dataSource.getHikariPoolMXBean().getActiveConnections());
                details.put("idleConnections", dataSource.getHikariPoolMXBean().getIdleConnections());
                details.put("maxConnections", dataSource.getMaximumPoolSize());
            }
            return new ComponentHealth("UP", details);
        } catch (Exception e) {
            details.put("error", e.getMessage());
            return new ComponentHealth("DOWN", details);
        }
    }

    private ComponentHealth checkVulnerabilitySyncHealth() {
        Map<String, Object> details = new HashMap<>();
        Map<String, JobStatus> jobs = statusService.getJobs();
        
        String status = "UP";
        Instant limit = Instant.now().minus(26, ChronoUnit.HOURS);
        Instant earliestNextRun = null;

        for (String jobId : new String[]{"osv-npm", "osv-pypi", "osv-maven", "ghsa", "openssf", "gitlab"}) {
            JobStatus job = jobs.get(jobId);
            if (job == null) {
                details.put(jobId, "MISSING");
                status = "DOWN";
                continue;
            }

            details.put(jobId, job.status());

            if (job.lastStartTime() == null) {
                details.put(jobId + "_neverRun", true);
            }

            // All vulnerability jobs share the same daily cron : if the job has no 
            // execution recorded in the database yet, we calculate the next occurrence directly.
            Instant jobNextRunTime = job.nextRunTime();
            Instant nextRunTime = jobNextRunTime != null ? jobNextRunTime : nextVulnerabilityCronExecution();
            details.put(jobId + "_nextRunTime", nextRunTime.toString());
            if (earliestNextRun == null || nextRunTime.isBefore(earliestNextRun)) {
                earliestNextRun = nextRunTime;
            }

            if ("FAILED".equals(job.status())) {
                status = "DOWN";
                details.put(jobId + "_error", job.errorMessage());
            } else if ("SUCCESS".equals(job.status())) {
                Instant jobLastEndTime = job.lastEndTime();
                if (jobLastEndTime != null && jobLastEndTime.isBefore(limit)) {
                    if (!"DOWN".equals(status)) {
                        status = "DEGRADED";
                    }
                    details.put(jobId + "_stale", true);
                }
            }
        }

        details.put("nextScheduledSync", earliestNextRun.toString());

        return new ComponentHealth(status, details);
    }

    private ComponentHealth checkGitOpsSyncHealth() {
        Map<String, Object> details = new HashMap<>();
        if (!properties.gitops().enabled()) {
            details.put("message", "GitOps is disabled in configuration");
            return new ComponentHealth("UP", details);
        }

        Map<String, JobStatus> jobs = statusService.getJobs();
        JobStatus gitopsJob = jobs.get("gitops-sync");

        if (gitopsJob == null) {
            details.put("message", "GitOps sync status row missing");
            return new ComponentHealth("DOWN", details);
        }

        details.put("status", gitopsJob.status());
        details.put("lastStartTime", gitopsJob.lastStartTime());
        details.put("lastEndTime", gitopsJob.lastEndTime());
        details.put("itemsProcessed", gitopsJob.itemsProcessed());
        if (gitopsJob.lastStartTime() == null) {
            details.put("neverRun", true);
        }

        // Until no execution has yet provided next_run_time in the database, we estimate the 
        // next occurrence based on the configured interval (fixedDelay).
        Instant gitopsNextRunTime = gitopsJob.nextRunTime();
        Instant nextRunTime = gitopsNextRunTime != null
                ? gitopsNextRunTime
                : Instant.now().plus(properties.gitops().syncIntervalMinutes(), ChronoUnit.MINUTES);
        details.put("nextRunTime", nextRunTime.toString());

        if ("FAILED".equals(gitopsJob.status())) {
            details.put("error", gitopsJob.errorMessage());
            return new ComponentHealth("DOWN", details);
        }

        if ("SUCCESS".equals(gitopsJob.status())) {
            Instant limit = Instant.now().minus(properties.gitops().syncIntervalMinutes() * 2L, ChronoUnit.MINUTES);
            Instant gitopsLastEndTime = gitopsJob.lastEndTime();
            if (gitopsLastEndTime != null && gitopsLastEndTime.isBefore(limit)) {
                details.put("message", "GitOps sync is stale (missed execution intervals)");
                return new ComponentHealth("DEGRADED", details);
            }
        }

        return new ComponentHealth("UP", details);
    }

    private Instant nextVulnerabilityCronExecution() {
        CronExpression cron = CronExpression.parse(VulnerabilitySyncScheduler.CRON_EXPRESSION);
        ZonedDateTime next = cron.next(ZonedDateTime.now());
        return next != null ? next.toInstant() : Instant.now().plus(1, ChronoUnit.DAYS);
    }
}
