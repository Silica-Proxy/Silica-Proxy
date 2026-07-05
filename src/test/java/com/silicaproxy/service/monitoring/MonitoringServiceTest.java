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
import com.zaxxer.hikari.HikariPoolMXBean;
import com.silicaproxy.dao.sync.HealthCheckDao;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.properties.SilicaProxyProperties.GitOpsProperties;
import com.silicaproxy.properties.SilicaProxyProperties.OsvIncrementalProperties;
import com.silicaproxy.service.interception.SslMitmService;
import com.silicaproxy.service.monitoring.MonitoringService.HealthReport;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService.JobStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MonitoringServiceTest {

    private MonitoringService monitoringService;

    @Mock
    private HealthCheckDao healthCheckDao;

    @Mock
    private VulnerabilitySyncStatusService statusService;

    @Mock
    private SilicaProxyProperties properties;

    @Mock
    private HikariDataSource dataSource;

    @Mock
    private SslMitmService sslMitmService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        monitoringService = new MonitoringService(healthCheckDao, statusService, properties, sslMitmService, dataSource);

        // Default mocks for GitOps (enabled, 10 min interval)
        GitOpsProperties gitopsProps = mock(GitOpsProperties.class);
        when(gitopsProps.enabled()).thenReturn(true);
        when(gitopsProps.syncIntervalMinutes()).thenReturn(10);
        when(properties.gitops()).thenReturn(gitopsProps);

        // Default mock for OSV incremental sync (enabled)
        OsvIncrementalProperties osvIncrementalProps = mock(OsvIncrementalProperties.class);
        when(osvIncrementalProps.enabled()).thenReturn(true);
        when(properties.osvIncremental()).thenReturn(osvIncrementalProps);

        // Default: CA certificate healthy, far from its 10-year expiry
        when(sslMitmService.getCaCertNotAfter()).thenReturn(Instant.now().plus(300, ChronoUnit.DAYS));
    }

    private void mockDatabaseOk() {
        when(healthCheckDao.isDatabaseReachable()).thenReturn(true);

        HikariPoolMXBean poolBean = mock(HikariPoolMXBean.class);
        when(poolBean.getActiveConnections()).thenReturn(2);
        when(poolBean.getIdleConnections()).thenReturn(8);
        when(dataSource.getHikariPoolMXBean()).thenReturn(poolBean);
        when(dataSource.getMaximumPoolSize()).thenReturn(10);
    }

    private Map<String, JobStatus> createDefaultOkJobs() {
        Map<String, JobStatus> jobs = new HashMap<>();
        Instant now = Instant.now();
        
        for (String jobId : new String[]{"osv-npm", "osv-pypi", "osv-maven", "ghsa", "openssf", "gitlab"}) {
            jobs.put(jobId, new JobStatus("SUCCESS", now.minus(2, ChronoUnit.HOURS), now.minus(2, ChronoUnit.HOURS), 5000L, null, 100L, now.plus(22, ChronoUnit.HOURS), null));
        }
        jobs.put("gitops-sync", new JobStatus("SUCCESS", now.minus(5, ChronoUnit.MINUTES), now.minus(5, ChronoUnit.MINUTES), 1000L, null, 10L, now.plus(5, ChronoUnit.MINUTES), null));
        for (String jobId : new String[]{"osv-npm-incremental", "osv-pypi-incremental", "osv-maven-incremental"}) {
            jobs.put(jobId, new JobStatus("SUCCESS", now.minus(30, ChronoUnit.MINUTES), now.minus(30, ChronoUnit.MINUTES), 500L, null, 5L, now.plus(30, ChronoUnit.MINUTES), null));
        }
        return jobs;
    }

    @Test
    void shouldReturnUpWhenEverythingIsOk() {
        mockDatabaseOk();
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("UP");
        assertThat(report.components().get("database").status()).isEqualTo("UP");
        assertThat(report.components().get("vulnerabilitySync").status()).isEqualTo("UP");
        assertThat(report.components().get("vulnerabilitySync").details()).containsKey("nextScheduledSync");
        assertThat(report.components().get("vulnerabilitySync").details()).containsKey("osv-npm_nextRunTime");
        assertThat(report.components().get("gitopsSync").status()).isEqualTo("UP");
        assertThat(report.components().get("gitopsSync").details()).containsKey("nextRunTime");
        assertThat(report.components().get("osvIncrementalSync").status()).isEqualTo("UP");
        assertThat(report.components().get("caCertificate").status()).isEqualTo("UP");
    }

    @Test
    void shouldReturnDownWhenDatabaseFails() {
        // Simuler une exception SQL
        when(healthCheckDao.isDatabaseReachable()).thenThrow(new RuntimeException("Database Connection Timeout"));
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("database").status()).isEqualTo("DOWN");
        assertThat(report.components().get("database").details().get("error")).isEqualTo("Database Connection Timeout");
    }

    @Test
    void shouldReturnDownWhenVulnerabilitySyncHasFailedJob() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Update a job to failed status
        jobs.put("gitlab", new JobStatus("FAILED", Instant.now(), Instant.now(), 200L, "Git connection reset", 0L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("vulnerabilitySync").status()).isEqualTo("DOWN");
        assertThat(report.components().get("vulnerabilitySync").details().get("gitlab_error")).isEqualTo("Git connection reset");
    }

    @Test
    void shouldReturnDegradedWhenVulnerabilitySyncIsStale() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Make the osv-npm job stale (more than 26 hours)
        Instant longAgo = Instant.now().minus(30, ChronoUnit.HOURS);
        jobs.put("osv-npm", new JobStatus("SUCCESS", longAgo, longAgo, 120000L, null, 15000L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("vulnerabilitySync").status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("vulnerabilitySync").details().get("osv-npm_stale")).isEqualTo(true);
    }

    @Test
    void shouldReturnDownWhenGitopsSyncHasFailed() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        jobs.put("gitops-sync", new JobStatus("FAILED", Instant.now(), Instant.now(), 100L, "Auth failed on policies repository", 0L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("gitopsSync").status()).isEqualTo("DOWN");
        assertThat(report.components().get("gitopsSync").details().get("error")).isEqualTo("Auth failed on policies repository");
    }

    @Test
    void shouldReturnDegradedWhenGitopsSyncIsStale() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Sync interval is 10 min. We make the last GitOps sync 25 minutes old (stale threshold = 20 min).
        Instant longAgo = Instant.now().minus(25, ChronoUnit.MINUTES);
        jobs.put("gitops-sync", new JobStatus("SUCCESS", longAgo, longAgo, 1000L, null, 10L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("gitopsSync").status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("gitopsSync").details().get("message")).isEqualTo("GitOps sync is stale (missed execution intervals)");
    }

    @Test
    void shouldHandleDisabledGitopsSync() {
        mockDatabaseOk();
        when(properties.gitops().enabled()).thenReturn(false);
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("UP");
        assertThat(report.components().get("gitopsSync").status()).isEqualTo("UP");
        assertThat(report.components().get("gitopsSync").details().get("message")).isEqualTo("GitOps is disabled in configuration");
    }

    @Test
    void shouldIndicateNeverRunForVulnerabilitySyncJobs() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Simulate a job that never ran (PENDING, no lastStartTime)
        jobs.put("osv-npm", new JobStatus("PENDING", null, null, null, null, 0L, Instant.now().plus(22, ChronoUnit.HOURS), null));
        jobs.put("ghsa", new JobStatus("PENDING", null, null, null, null, 0L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.components().get("vulnerabilitySync").details().get("osv-npm")).isEqualTo("PENDING");
        assertThat(report.components().get("vulnerabilitySync").details().get("osv-npm_neverRun")).isEqualTo(true);
        assertThat(report.components().get("vulnerabilitySync").details().get("ghsa")).isEqualTo("PENDING");
        assertThat(report.components().get("vulnerabilitySync").details().get("ghsa_neverRun")).isEqualTo(true);
        // Jobs that have run must not have the flag
        assertThat(report.components().get("vulnerabilitySync").details()).doesNotContainKey("gitlab_neverRun");
    }

    @Test
    void shouldComputeNextRunTimeLiveWhenNoJobHasEverRun() {
        // Case of a brand new database : all jobs are PENDING, never executed,
        // so next_run_time has never been written to the database (null for all).
        mockDatabaseOk();
        Map<String, JobStatus> jobs = new HashMap<>();
        for (String jobId : new String[]{"osv-npm", "osv-pypi", "osv-maven", "ghsa", "openssf", "gitlab"}) {
            jobs.put(jobId, new JobStatus("PENDING", null, null, null, null, 0L, null, null));
        }
        jobs.put("gitops-sync", new JobStatus("PENDING", null, null, null, null, 0L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.components().get("vulnerabilitySync").details()).containsKey("nextScheduledSync");
        assertThat(report.components().get("vulnerabilitySync").details()).containsKey("osv-npm_nextRunTime");
        assertThat(report.components().get("vulnerabilitySync").details()).containsKey("ghsa_nextRunTime");
        assertThat(report.components().get("gitopsSync").details()).containsKey("nextRunTime");
    }

    @Test
    void shouldIndicateNeverRunForGitopsSync() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Simulate a gitops-sync that never ran
        jobs.put("gitops-sync", new JobStatus("PENDING", null, null, null, null, 0L, Instant.now().plus(5, ChronoUnit.MINUTES), null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.components().get("gitopsSync").status()).isEqualTo("UP");
        assertThat(report.components().get("gitopsSync").details().get("status")).isEqualTo("PENDING");
        assertThat(report.components().get("gitopsSync").details().get("neverRun")).isEqualTo(true);
        assertThat(report.components().get("gitopsSync").details()).containsKey("nextRunTime");
    }

    @Test
    void shouldReturnDownWhenVulnerabilityJobIsMissing() {
        // If a vulnerability job is missing from the map (spec §6.2), the status must be DOWN
        // with the detail containing "MISSING" (MonitoringService L120-123).
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Remove a vulnerability job
        jobs.remove("osv-npm");
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("vulnerabilitySync").status()).isEqualTo("DOWN");
        assertThat(report.components().get("vulnerabilitySync").details()).containsEntry("osv-npm", "MISSING");
    }

    @Test
    void shouldReturnDegradedWhenOsvIncrementalSyncIsStale() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Hourly job stale threshold is 3 hours (much shorter than the 26h daily-batch one).
        Instant longAgo = Instant.now().minus(4, ChronoUnit.HOURS);
        jobs.put("osv-npm-incremental", new JobStatus("SUCCESS", longAgo, longAgo, 500L, null, 5L, null, null));
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("osvIncrementalSync").status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("osvIncrementalSync").details().get("osv-npm-incremental_stale")).isEqualTo(true);
    }

    @Test
    void shouldReturnDownWhenOsvIncrementalJobIsMissing() {
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        jobs.remove("osv-pypi-incremental");
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("osvIncrementalSync").status()).isEqualTo("DOWN");
        assertThat(report.components().get("osvIncrementalSync").details()).containsEntry("osv-pypi-incremental", "MISSING");
    }

    @Test
    void shouldHandleDisabledOsvIncrementalSync() {
        mockDatabaseOk();
        OsvIncrementalProperties disabledProps = mock(OsvIncrementalProperties.class);
        when(disabledProps.enabled()).thenReturn(false);
        when(properties.osvIncremental()).thenReturn(disabledProps);
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("UP");
        assertThat(report.components().get("osvIncrementalSync").status()).isEqualTo("UP");
        assertThat(report.components().get("osvIncrementalSync").details().get("message"))
                .isEqualTo("OSV incremental sync is disabled in configuration");
    }

    @Test
    void shouldReturnDownWhenGitOpsSyncJobIsMissing() {
        // If the gitops-sync job is missing from the map (spec §6.2), the status must be DOWN
        // with message "GitOps sync status row missing" (MonitoringService L170-173).
        mockDatabaseOk();
        Map<String, JobStatus> jobs = createDefaultOkJobs();
        // Retirer le job gitops-sync
        jobs.remove("gitops-sync");
        when(statusService.getJobs()).thenReturn(jobs);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("gitopsSync").status()).isEqualTo("DOWN");
        assertThat(report.components().get("gitopsSync").details().get("message"))
                .isEqualTo("GitOps sync status row missing");
    }

    @Test
    void shouldReturnDegradedWhenCaCertificateExpiresSoon() {
        mockDatabaseOk();
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());
        when(sslMitmService.getCaCertNotAfter()).thenReturn(Instant.now().plus(10, ChronoUnit.DAYS));

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("caCertificate").status()).isEqualTo("DEGRADED");
        assertThat(report.components().get("caCertificate").details().get("daysRemaining")).isEqualTo(9L);
    }

    @Test
    void shouldReturnDownWhenCaCertificateHasExpired() {
        mockDatabaseOk();
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());
        when(sslMitmService.getCaCertNotAfter()).thenReturn(Instant.now().minus(1, ChronoUnit.DAYS));

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("caCertificate").status()).isEqualTo("DOWN");
        assertThat(report.components().get("caCertificate").details().get("message"))
                .isEqualTo("CA certificate has expired -- TLS interception is broken for every client that trusts it");
    }

    @Test
    void shouldReturnDownWhenCaCertificateNotYetInitialized() {
        mockDatabaseOk();
        when(statusService.getJobs()).thenReturn(createDefaultOkJobs());
        when(sslMitmService.getCaCertNotAfter()).thenReturn(null);

        HealthReport report = monitoringService.checkHealth();

        assertThat(report.status()).isEqualTo("DOWN");
        assertThat(report.components().get("caCertificate").status()).isEqualTo("DOWN");
        assertThat(report.components().get("caCertificate").details().get("message"))
                .isEqualTo("CA certificate not yet initialized");
    }
}
