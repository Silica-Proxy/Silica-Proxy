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
import org.junit.jupiter.api.Test;

import java.time.YearMonth;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

class PartitionMaintenanceServiceTest {

    @Test
    void shouldEnsurePartitionsForCurrentAndNextThreeMonthsForEachManagedTable() {
        PartitionMaintenanceDao dao = mock(PartitionMaintenanceDao.class);
        PartitionMaintenanceService service = new PartitionMaintenanceService(dao);
        YearMonth reference = YearMonth.of(2099, 6);

        service.ensureFuturePartitionsExist(reference);

        for (int i = 0; i <= 3; i++) {
            verify(dao).ensureMonthlyPartitionExists("proxy_audit_logs", reference.plusMonths(i));
            verify(dao).ensureMonthlyPartitionExists("api_call_log", reference.plusMonths(i));
        }
        verifyNoMoreInteractions(dao);
    }

    @Test
    void shouldNotCreatePartitionsBeforeTheReferenceMonth() {
        PartitionMaintenanceDao dao = mock(PartitionMaintenanceDao.class);
        PartitionMaintenanceService service = new PartitionMaintenanceService(dao);
        YearMonth reference = YearMonth.of(2099, 6);

        service.ensureFuturePartitionsExist(reference);

        verify(dao, org.mockito.Mockito.never())
                .ensureMonthlyPartitionExists("proxy_audit_logs", reference.minusMonths(1));
        verify(dao, org.mockito.Mockito.never())
                .ensureMonthlyPartitionExists("proxy_audit_logs", reference.plusMonths(4));
    }

    @Test
    void scheduledEntryPointShouldUseTheCurrentMonth() {
        PartitionMaintenanceDao dao = mock(PartitionMaintenanceDao.class);
        PartitionMaintenanceService service = new PartitionMaintenanceService(dao);

        service.ensureFuturePartitionsExist();

        verify(dao).ensureMonthlyPartitionExists("proxy_audit_logs", YearMonth.now());
        verify(dao).ensureMonthlyPartitionExists("api_call_log", YearMonth.now());
    }
}
