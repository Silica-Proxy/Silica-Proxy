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

import com.silicaproxy.dao.audit.PartitionMaintenanceDao;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.YearMonth;
import java.util.List;

/**
 * Keeps the partitioned audit tables ({@code proxy_audit_logs}, {@code api_call_log}) supplied
 * with partitions ahead of need. Flyway only creates a handful of partitions at migration time
 * (see V1/V7); without this, inserts start failing with "no partition of relation found for row"
 * once the last pre-created month passes. Unlike the in-memory caches elsewhere in this package
 * family, the partitions themselves are a database resource shared by every instance, so this
 * runs under a SchedulerLock via PartitionMaintenanceScheduler rather than independently per instance.
 */
@Service
@NullMarked
public class PartitionMaintenanceService {

    private static final Logger LOG = LoggerFactory.getLogger(PartitionMaintenanceService.class);

    private static final List<String> MANAGED_PARTITIONED_TABLES = List.of("proxy_audit_logs", "api_call_log");
    // How many months beyond the current one to keep pre-created. Generous relative to the
    // once-daily schedule below, so a missed run or a delayed deploy doesn't risk running out.
    private static final int MONTHS_AHEAD = 3;

    private final PartitionMaintenanceDao partitionMaintenanceDao;

    public PartitionMaintenanceService(PartitionMaintenanceDao partitionMaintenanceDao) {
        this.partitionMaintenanceDao = partitionMaintenanceDao;
    }

    public void ensureFuturePartitionsExist() {
        ensureFuturePartitionsExist(YearMonth.now());
    }

    /** Package-visible entry point taking an explicit reference month, so tests don't depend on
     * (or risk colliding with) the real wall-clock month. */
    void ensureFuturePartitionsExist(YearMonth referenceMonth) {
        for (String table : MANAGED_PARTITIONED_TABLES) {
            for (int i = 0; i <= MONTHS_AHEAD; i++) {
                partitionMaintenanceDao.ensureMonthlyPartitionExists(table, referenceMonth.plusMonths(i));
            }
        }
        LOG.info("Ensured partitions exist from {} through {} for tables {}",
                referenceMonth, referenceMonth.plusMonths(MONTHS_AHEAD), MANAGED_PARTITIONED_TABLES);
    }
}
