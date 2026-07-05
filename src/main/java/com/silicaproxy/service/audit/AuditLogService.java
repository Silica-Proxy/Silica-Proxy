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


package com.silicaproxy.service.audit;

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.audit.AuditLogDao;
import com.silicaproxy.model.entity.AuditLog;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import io.micrometer.core.annotation.Timed;

import java.time.Instant;

/**
 * Builds and writes (asynchronously, via {@code @Async("auditTaskExecutor")}) an audit line
 * for each proxy decision. Called by {@code ProxyController} immediately after
 * each ALLOW/BLOCK verdict, never blocking the HTTP response to the client.
 */
@Service
@NullMarked
public class AuditLogService {

    private static final Logger LOG = LoggerFactory.getLogger(AuditLogService.class);

    private final AuditLogDao auditLogDao;
    private final MeterRegistry meterRegistry;

    public AuditLogService(AuditLogDao auditLogDao, MeterRegistry meterRegistry) {
        this.auditLogDao = auditLogDao;
        this.meterRegistry = meterRegistry;
    }

    @Async("auditTaskExecutor")
    @Timed(value = "silicaproxy.service.auditlog.logaudit",
            description = "Duration of async audit log processing by AuditLogService",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void logAudit(
            String packageName,
            String packageVersion,
            String ecosystem,
            String decisionSource,
            String verdict,
            @Nullable String reason,
            int executionTimeMs) {

        AuditLog auditLog = new AuditLog(
                null,
                Instant.now(),
                packageName,
                packageVersion,
                ecosystem,
                decisionSource,
                verdict,
                reason,
                executionTimeMs
        );

        // Runs on the audit executor (see AsyncConfig), whose default async-exception handler
        // only logs and drops -- catching here instead lets a failed write surface as a
        // Prometheus counter (silicaproxy_service_auditlog_writes_total), otherwise a broken
        // audit trail (disk full, constraint violation) would be invisible on every dashboard.
        try {
            auditLogDao.save(auditLog);
            recordWriteOutcome(Metrics.OUTCOME_SUCCESS);
        } catch (RuntimeException e) {
            recordWriteOutcome(Metrics.OUTCOME_FAILURE);
            LOG.error("Failed to write audit log for {}/{} ({}): {}",
                    ecosystem, packageName, packageVersion, e.getMessage(), e);
        }
    }

    private void recordWriteOutcome(String outcome) {
        Counter.builder(Metrics.AUDIT_LOG_WRITES_METRIC)
                .description("Total number of audit log write attempts, by outcome (SUCCESS/FAILURE)")
                .tag(Metrics.TAG_OUTCOME, outcome)
                .register(meterRegistry)
                .increment();
    }
}
