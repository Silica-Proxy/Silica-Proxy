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
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled component responsible for PostgreSQL partition maintenance.
 * Delegates the actual partitioning operations to {@link PartitionMaintenanceService}.
 * Coordinated across multiple instances using ShedLock.
 */
@Component
@NullMarked
public class PartitionMaintenanceScheduler {

    private static final Logger LOG = LoggerFactory.getLogger(PartitionMaintenanceScheduler.class);

    private final PartitionMaintenanceService partitionMaintenanceService;

    public PartitionMaintenanceScheduler(PartitionMaintenanceService partitionMaintenanceService) {
        this.partitionMaintenanceService = partitionMaintenanceService;
    }

    @Scheduled(cron = "0 0 3 * * *")
    @SchedulerLock(name = "partition_maintenance_lock", lockAtMostFor = "5m", lockAtLeastFor = "10s")
    public void ensureFuturePartitionsExist() {
        LOG.info("Starting scheduled partition maintenance task...");
        partitionMaintenanceService.ensureFuturePartitionsExist();
    }
}
