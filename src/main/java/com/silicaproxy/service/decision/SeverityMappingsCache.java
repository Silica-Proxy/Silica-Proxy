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

import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.model.entity.SeverityMapping;
import jakarta.annotation.PostConstruct;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory cache of the {@code severity_mappings} reference table (severity level -> CVSS
 * range), consulted by {@link SecurityService} to resolve the CVSS floor for a given maximum
 * allowed severity. Loaded once at startup and refreshed periodically by
 * {@link SeverityMappingsRefreshService} rather than only at startup, so an administrator
 * updating this small reference table doesn't require restarting every instance. Purely local,
 * per-instance state: no cross-instance coordination is involved.
 */
@Component
@NullMarked
public class SeverityMappingsCache {

    private static final Logger LOG = LoggerFactory.getLogger(SeverityMappingsCache.class);

    private final DecisionDao decisionDao;
    private final Map<String, SeverityMapping> mappings = new ConcurrentHashMap<>();

    public SeverityMappingsCache(DecisionDao decisionDao) {
        this.decisionDao = decisionDao;
    }

    @PostConstruct
    void init() {
        refresh();
    }

    /**
     * Reloads all mappings from the database. Loads into a separate map first and only swaps it
     * in on success, so a transient DB error leaves the previous, still-valid mappings in place
     * rather than wiping them.
     */
    public void refresh() {
        try {
            Map<String, SeverityMapping> loaded = new ConcurrentHashMap<>();
            for (SeverityMapping mapping : decisionDao.findAllSeverityMappings()) {
                loaded.put(mapping.severityLevel().toUpperCase(), mapping);
            }
            mappings.clear();
            mappings.putAll(loaded);
        } catch (Exception e) {
            LOG.error("Error while loading severity mappings; keeping previous values", e);
        }
    }

    public @Nullable SeverityMapping get(String severityLevel) {
        return mappings.get(severityLevel);
    }
}
