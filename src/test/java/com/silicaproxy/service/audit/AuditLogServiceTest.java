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

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.dao.audit.AuditLogDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.reset;

class AuditLogServiceTest extends BaseIntegrationTest {

    private final AuditLogService auditLogService;
    private final JdbcClient jdbcClient;
    private final Executor auditTaskExecutor;

    @MockitoSpyBean
    private AuditLogDao spyAuditLogDao;

    @Autowired
    AuditLogServiceTest(
            AuditLogService auditLogService,
            JdbcClient jdbcClient,
            @Qualifier("auditTaskExecutor") Executor auditTaskExecutor) {
        this.auditLogService = auditLogService;
        this.jdbcClient = jdbcClient;
        this.auditTaskExecutor = auditTaskExecutor;
    }

    @BeforeEach
    void cleanDb() {
        jdbcClient.sql("TRUNCATE proxy_audit_logs RESTART IDENTITY CASCADE").update();
        reset(spyAuditLogDao);
    }

    @Test
    void shouldLogAuditAsynchronously() throws Exception {
        // Sending an audit request
        auditLogService.logAudit(
                "async-pkg",
                "1.0.0",
                "npm",
                "COMPANY_POLICY",
                "ALLOW",
                "Passed checks",
                15
        );

        // Attente de l'insertion asynchrone (Awaitility-like loop)
        int attempts = 0;
        List<Map<String, Object>> logs = List.of();
        while (attempts < 50) {
            logs = jdbcClient.sql("SELECT * FROM proxy_audit_logs WHERE package_name = 'async-pkg'").query().listOfRows();
            if (!logs.isEmpty()) {
                break;
            }
            Thread.sleep(50);
            attempts++;
        }

        assertThat(logs).hasSize(1);
        Map<String, Object> logRow = logs.get(0);
        assertThat(logRow.get("package_version")).isEqualTo("1.0.0");
        assertThat(logRow.get("ecosystem")).isEqualTo("npm");
        assertThat(logRow.get("decision_source")).isEqualTo("COMPANY_POLICY");
        assertThat(logRow.get("verdict")).isEqualTo("ALLOW");
        assertThat(logRow.get("reason")).isEqualTo("Passed checks");
        assertThat((Integer) logRow.get("execution_time_ms")).isEqualTo(15);
    }

    @Test
    void shouldDiscardOldestWhenQueueIsFull() throws Exception {
        ThreadPoolTaskExecutor executor = (ThreadPoolTaskExecutor) auditTaskExecutor;
        int corePoolSize = executor.getCorePoolSize();
        int maxPoolSize = executor.getMaxPoolSize();
        int queueCapacity = executor.getQueueCapacity();

        CountDownLatch blockLatch = new CountDownLatch(1);
        CountDownLatch startedLatch = new CountDownLatch(maxPoolSize);

        List<String> executedTasks = Collections.synchronizedList(new ArrayList<>());

        // 1. Submit corePoolSize blocking tasks to keep core threads busy
        for (int i = 0; i < corePoolSize; i++) {
            executor.execute(() -> {
                startedLatch.countDown();
                try {
                    blockLatch.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        // 2. Fill the queue with queueCapacity tasks
        for (int i = 0; i < queueCapacity; i++) {
            final String name = "queue-" + i;
            executor.execute(() -> executedTasks.add(name));
        }

        // 3. Submit maxPoolSize - corePoolSize blocking tasks to force creation of max threads
        for (int i = 0; i < (maxPoolSize - corePoolSize); i++) {
            executor.execute(() -> {
                startedLatch.countDown();
                try {
                    blockLatch.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        // 4. Wait for all maxPoolSize threads to start and block
        boolean threadsStarted = startedLatch.await(10, TimeUnit.SECONDS);
        assertThat(threadsStarted).isTrue();

        // 5. Submit overflow task
        final String overflowName = "overflow";
        executor.execute(() -> executedTasks.add(overflowName));

        // 6. Unblock all threads
        blockLatch.countDown();

        // 7. Wait for all tasks to be executed
        int attempts = 0;
        while (executor.getActiveCount() > 0 || executor.getQueueSize() > 0) {
            Thread.sleep(50);
            if (attempts++ > 150) {
                break;
            }
        }

        // 8. Assertions:
        // "queue-0" should have been discarded
        assertThat(executedTasks).doesNotContain("queue-0");
        assertThat(executedTasks).contains("overflow");
        assertThat(executedTasks).contains("queue-1");
    }
}
