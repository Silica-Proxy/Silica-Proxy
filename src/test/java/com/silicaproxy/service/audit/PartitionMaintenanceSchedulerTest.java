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

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.Scheduled;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PartitionMaintenanceSchedulerTest {

    @Test
    void shouldDelegateToPartitionMaintenanceService() {
        PartitionMaintenanceService service = mock(PartitionMaintenanceService.class);
        PartitionMaintenanceScheduler scheduler = new PartitionMaintenanceScheduler(service);

        scheduler.ensureFuturePartitionsExist();

        verify(service).ensureFuturePartitionsExist();
    }

    @Test
    void shouldHaveScheduledAnnotationWithCorrectCron() throws NoSuchMethodException {
        Method method = PartitionMaintenanceScheduler.class.getMethod("ensureFuturePartitionsExist");
        Scheduled scheduled = method.getAnnotation(Scheduled.class);

        assertThat(scheduled).isNotNull();
        assertThat(scheduled.cron()).isEqualTo("0 0 3 * * *");
    }

    @Test
    void shouldHaveSchedulerLockAnnotationWithCorrectConfiguration() throws NoSuchMethodException {
        Method method = PartitionMaintenanceScheduler.class.getMethod("ensureFuturePartitionsExist");
        SchedulerLock schedulerLock = method.getAnnotation(SchedulerLock.class);

        assertThat(schedulerLock).isNotNull();
        assertThat(schedulerLock.name()).isEqualTo("partition_maintenance_lock");
        assertThat(schedulerLock.lockAtMostFor()).isEqualTo("5m");
        assertThat(schedulerLock.lockAtLeastFor()).isEqualTo("10s");
    }
}
