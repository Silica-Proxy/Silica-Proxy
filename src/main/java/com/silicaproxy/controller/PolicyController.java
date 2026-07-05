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

import com.silicaproxy.config.ApiKeyScope;
import com.silicaproxy.config.RequiresApiKey;
import com.silicaproxy.model.dto.PolicyEvaluationResponse;
import com.silicaproxy.model.dto.PolicySimulationRequest;
import com.silicaproxy.service.policy.PolicySimulationService;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

/**
 * Exposes two endpoints to help understand conflict resolution between
 * {@code company_policies} rules :
 * <ul>
 *   <li>{@code GET /api/policies/evaluate} — evaluates a package/version against rules in database
 *       and returns ALLOWED, BLOCKED or NO_MATCH with details of each matching rule.</li>
 *   <li>{@code POST /api/policies/simulate} — same logic but with rules provided in the
 *       request body, without touching the database.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/policies")
@NullMarked
public class PolicyController {

    private static final Logger LOG = LoggerFactory.getLogger(PolicyController.class);

    private final PolicySimulationService policySimulationService;

    public PolicyController(PolicySimulationService policySimulationService) {
        this.policySimulationService = policySimulationService;
    }

    private static String sanitizeLog(String s) {
        return s == null ? null : s.replace('\n', ' ').replace('\r', ' ');
    }

    @RequiresApiKey(ApiKeyScope.READ)
    @GetMapping("/evaluate")
    public ResponseEntity<?> evaluate(
            @RequestParam String ecosystem,
            @RequestParam String packageName,
            @RequestParam String version) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Evaluating rules in database : ecosystem={}, package={}, version={}",
                    sanitizeLog(ecosystem), sanitizeLog(packageName), sanitizeLog(version));
        }

        PolicyEvaluationResponse response = policySimulationService.evaluateFromDb(
                packageName, version, ecosystem);
        return ResponseEntity.ok(response);
    }

    @RequiresApiKey(ApiKeyScope.READ)
    @PostMapping("/simulate")
    public ResponseEntity<?> simulate(@RequestBody PolicySimulationRequest request) {
        if (request.ecosystem() == null || request.ecosystem().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "The 'ecosystem' field is required"));
        }
        if (request.packageName() == null || request.packageName().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "The 'packageName' field is required"));
        }
        if (request.version() == null || request.version().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "The 'version' field is required"));
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Rules simulation : ecosystem={}, package={}, version={}, {} rules",
                    sanitizeLog(request.ecosystem()), sanitizeLog(request.packageName()),
                    sanitizeLog(request.version()), request.policies().size());
        }

        PolicyEvaluationResponse response = policySimulationService.simulate(request);
        return ResponseEntity.ok(response);
    }
}
