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


package com.silicaproxy.service.monitoring;

import com.silicaproxy.dao.policy.GitOpsDao;
import com.silicaproxy.dao.vulnerability.VulnerabilityDao;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Calculates the volume of currently loaded data (public vulnerabilities and governance rules, 
 * by ecosystem). Logged once at instance startup via
 * {@link ApplicationReadyEvent}, and continuously exposed via the {@code dataInventory} field of
 * {@code GET /api/vulnerabilities/sync/status} .
 */
@Service
@NullMarked
public class DataInventoryService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataInventoryService.class);

    private final VulnerabilityDao vulnerabilityDao;
    private final GitOpsDao gitOpsDao;

    public DataInventoryService(VulnerabilityDao vulnerabilityDao, GitOpsDao gitOpsDao) {
        this.vulnerabilityDao = vulnerabilityDao;
        this.gitOpsDao = gitOpsDao;
    }

    public record DataInventory(
            long totalVulnerabilities,
            Map<String, Long> vulnerabilitiesByEcosystem,
            long totalPolicies,
            Map<String, Long> policiesByEcosystem
    ) {
        public DataInventory {
            vulnerabilitiesByEcosystem = Collections.unmodifiableMap(new HashMap<>(vulnerabilitiesByEcosystem));
            policiesByEcosystem = Collections.unmodifiableMap(new HashMap<>(policiesByEcosystem));
        }
    }

    public DataInventory getInventory() {
        Map<String, Long> vulnerabilitiesByEcosystem = vulnerabilityDao.countByEcosystem();
        Map<String, Long> policiesByEcosystem = gitOpsDao.countPoliciesByEcosystem();

        return new DataInventory(
                vulnerabilitiesByEcosystem.values().stream().mapToLong(Long::longValue).sum(),
                vulnerabilitiesByEcosystem,
                policiesByEcosystem.values().stream().mapToLong(Long::longValue).sum(),
                policiesByEcosystem
        );
    }

    // Provides an immediate view of the loaded data volume from instance startup,
    // even before the first scheduled execution (useful in dev and for production diagnostics).
    @EventListener(ApplicationReadyEvent.class)
    public void logInventoryOnStartup() {
        DataInventory inventory = getInventory();
        LOGGER.info(
                "Data inventory at startup: {} public vulnerabilities {}, {} company policies {}",
                inventory.totalVulnerabilities(), inventory.vulnerabilitiesByEcosystem(),
                inventory.totalPolicies(), inventory.policiesByEcosystem());
    }
}
