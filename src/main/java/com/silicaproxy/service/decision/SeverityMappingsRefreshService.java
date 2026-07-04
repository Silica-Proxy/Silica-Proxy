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

import org.jspecify.annotations.NullMarked;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Scheduled refresh of {@link SeverityMappingsCache}. Runs independently on every instance (no
 * ShedLock): the cache is purely in-process state, not shared across instances, so there is
 * nothing to coordinate.
 */
@Service
@NullMarked
public class SeverityMappingsRefreshService {

    private final SeverityMappingsCache severityMappingsCache;

    public SeverityMappingsRefreshService(SeverityMappingsCache severityMappingsCache) {
        this.severityMappingsCache = severityMappingsCache;
    }

    @Scheduled(fixedRate = 3_600_000)
    void refresh() {
        severityMappingsCache.refresh();
    }
}
