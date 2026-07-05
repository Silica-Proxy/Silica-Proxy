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
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * Groups the two read-through cache collaborators consulted by {@link SecurityService} outside
 * of the primary {@code DecisionDao} SQL evaluation (package metadata/API-verdict cache and the
 * in-memory severity-mappings cache), purely to keep {@code SecurityService}'s constructor under
 * PMD's ExcessiveParameterList threshold of 8 -- unlike {@code VulnerabilityApiClients}, these
 * two are not used together in any single code path.
 */
@Component
@NullMarked
public class SecurityServiceCaches {

    private final MetadataCacheDao metadataCacheDao;
    private final SeverityMappingsCache severityMappingsCache;

    public SecurityServiceCaches(MetadataCacheDao metadataCacheDao, SeverityMappingsCache severityMappingsCache) {
        this.metadataCacheDao = metadataCacheDao;
        this.severityMappingsCache = severityMappingsCache;
    }

    public MetadataCacheDao metadataCacheDao() {
        return metadataCacheDao;
    }

    public SeverityMappingsCache severityMappingsCache() {
        return severityMappingsCache;
    }
}
