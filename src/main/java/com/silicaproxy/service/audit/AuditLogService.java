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

import com.silicaproxy.dao.audit.AuditLogDao;
import com.silicaproxy.model.entity.AuditLog;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
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

    private final AuditLogDao auditLogDao;

    public AuditLogService(AuditLogDao auditLogDao) {
        this.auditLogDao = auditLogDao;
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

        auditLogDao.save(auditLog);
    }
}
