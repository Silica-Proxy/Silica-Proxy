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

import com.silicaproxy.dao.policy.MetadataCacheDao;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Service dedicated to scheduled cleanup of expired API cache.
 * Regularly purges expired entries from the {@code api_cache} table.
 */
@Service
public class ApiCacheCleanupService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiCacheCleanupService.class);

    private final MetadataCacheDao metadataCacheDao;

    public ApiCacheCleanupService(MetadataCacheDao metadataCacheDao) {
        this.metadataCacheDao = metadataCacheDao;
    }

    @Scheduled(cron = "* * * * * *") // Every minute
    @SchedulerLock(name = "clean_api_cache_lock", lockAtMostFor = "1m", lockAtLeastFor = "5s")
    public void cleanExpiredApiCache() {
        LOGGER.debug("Starting cleanup of expired API cache...");
        try {
            int deleted = metadataCacheDao.deleteExpiredApiCache();
            if (deleted > 0) {
                LOGGER.info("Cleaned up {} expired entries from api_cache.", deleted);
            }
        } catch (Exception e) {
            LOGGER.error("Failed to clean API cache", e);
        }
    }
}
