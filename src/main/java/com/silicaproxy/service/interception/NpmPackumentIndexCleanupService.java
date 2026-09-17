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


package com.silicaproxy.service.interception;

import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Scheduled eviction of expired entries from {@link NpmPackumentIndex}. Same rationale as
 * {@link SslContextCacheCleanupService} : purely in-process state, no ShedLock needed.
 */
@Service
@NullMarked
public class NpmPackumentIndexCleanupService {

    private static final Logger LOG = LoggerFactory.getLogger(NpmPackumentIndexCleanupService.class);

    private final NpmPackumentIndex npmPackumentIndex;

    public NpmPackumentIndexCleanupService(NpmPackumentIndex npmPackumentIndex) {
        this.npmPackumentIndex = npmPackumentIndex;
    }

    @Scheduled(fixedRate = 300_000)
    void evictExpiredTarballs() {
        int evicted = npmPackumentIndex.evictStaleEntries(npmPackumentIndex.ttl());
        if (evicted > 0) {
            LOG.info("Evicted {} expired npm tarball index entries (older than {}), {} remaining",
                    evicted, npmPackumentIndex.ttl(), npmPackumentIndex.size());
        }
    }
}
