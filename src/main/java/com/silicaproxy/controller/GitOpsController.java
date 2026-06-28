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


package com.silicaproxy.controller;

import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.policy.GitOpsSyncService;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

/**
 * Exposes {@code POST /api/gitops/sync/force}  to manually trigger the
 * synchronization of GitOps governance rules outside the scheduled cycle 
 * ({@code sync-interval-minutes}, 10 min by default). Called on demand (ex: after a 
 * rule modification, to apply it immediately) ; refuses if GitOps is disabled in 
 * configuration or if a synchronization is already in progress.
 */
@RestController
@RequestMapping("/api/gitops/sync")
@NullMarked
public class GitOpsController {

    private static final Logger LOG = LoggerFactory.getLogger(GitOpsController.class);

    private final GitOpsSyncService gitOpsSyncService;
    private final VulnerabilitySyncStatusService statusService;
    private final SilicaProxyProperties properties;

    public GitOpsController(
            GitOpsSyncService gitOpsSyncService,
            VulnerabilitySyncStatusService statusService,
            SilicaProxyProperties properties) {
        this.gitOpsSyncService = gitOpsSyncService;
        this.statusService = statusService;
        this.properties = properties;
    }

    @PostMapping("/force")
    public ResponseEntity<Map<String, String>> forceSync() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("GitOps force synchronization request received.");
        }
        if (!properties.gitops().enabled()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cancellation : GitOps is disabled in configuration.");
            }
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "GitOps synchronization is disabled in configuration"));
        }

        if (statusService.isJobRunning("gitops-sync")) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Conflict : a GitOps synchronization is already running.");
            }
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", "GitOps synchronization is already running"));
        }

        Thread.startVirtualThread(() -> {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Starting GitOps rules synchronization in a virtual thread.");
                }
                gitOpsSyncService.syncCompanyPolicies();
            } catch (Exception e) {
                // Logged inside service
            }
        });

        return ResponseEntity.accepted()
                .body(Map.of("message", "GitOps synchronization started"));
    }
}
