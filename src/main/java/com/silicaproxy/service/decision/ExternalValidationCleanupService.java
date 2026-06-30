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


package com.silicaproxy.service.decision;

import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class ExternalValidationCleanupService {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalValidationCleanupService.class);

    private final ExternalValidationCacheDao cacheDao;

    public ExternalValidationCleanupService(ExternalValidationCacheDao cacheDao) {
        this.cacheDao = cacheDao;
    }

    @Scheduled(cron = "0 * * * * *")
    @SchedulerLock(name = "external_validation_cleanup",
            lockAtMostFor = "1m", lockAtLeastFor = "5s")
    public void cleanup() {
        try {
            int timedOut = cacheDao.expireTimedOutPending();
            int deleted  = cacheDao.deleteExpiredEntries();
            if (timedOut > 0 || deleted > 0) {
                LOG.info("ExternalValidation cleanup: {} PENDING→TIMEOUT, {} entries deleted",
                        timedOut, deleted);
            }
        } catch (Exception e) {
            LOG.error("ExternalValidation cleanup failed", e);
        }
    }
}
