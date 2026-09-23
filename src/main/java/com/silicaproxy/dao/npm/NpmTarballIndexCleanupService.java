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


package com.silicaproxy.dao.npm;

import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.stereotype.Service;

/**
 * Scheduled eviction of expired entries from {@link NpmTarballIndexDao}. Runs on only one
 * instance at a time via ShedLock (database-coordinated), since the table is shared across
 * all instances. Prevents unbounded growth and duplicate cleanup work.
 */
@Service
@NullMarked
public class NpmTarballIndexCleanupService {

    private static final Logger LOG = LoggerFactory.getLogger(NpmTarballIndexCleanupService.class);

    private final NpmTarballIndexDao npmTarballIndexDao;

    public NpmTarballIndexCleanupService(NpmTarballIndexDao npmTarballIndexDao) {
        this.npmTarballIndexDao = npmTarballIndexDao;
    }

    /**
     * Evicts entries past their TTL (every 5 minutes). Runs on only one instance at a time
     * via ShedLock, since the table is shared across all instances.
     */
    @Scheduled(fixedRate = 300_000)
    @SchedulerLock(name = "evictExpiredNpmTarballs", lockAtMostFor = "4m59s", lockAtLeastFor = "30s")
    void evictExpiredTarballs() {
        int evicted = npmTarballIndexDao.evictExpired();
        if (evicted > 0) {
            LOG.info("Evicted {} expired npm tarball index entries from database, {} remaining",
                    evicted, npmTarballIndexDao.count());
        }
    }
}
