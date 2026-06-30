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

import com.silicaproxy.dao.client.ExternalValidationClient;
import com.silicaproxy.dao.client.ExternalValidationClient.ExternalValidationResult;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.properties.SilicaProxyProperties.ExternalValidationServiceProperties;
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

@Service
@NullMarked
public class ExternalValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalValidationService.class);

    private static final String BLOCKED = "BLOCKED";
    private static final String ALLOWED = "ALLOWED";

    private final SilicaProxyProperties properties;
    private final ExternalValidationCacheDao cacheDao;
    private final ExternalValidationVerdictsDao verdictsDao;
    private final ExternalValidationClient client;
    private final Executor asyncExecutor;

    public ExternalValidationService(
            SilicaProxyProperties properties,
            ExternalValidationCacheDao cacheDao,
            ExternalValidationVerdictsDao verdictsDao,
            ExternalValidationClient client,
            @Qualifier("externalValidationExecutor") Executor asyncExecutor) {
        this.properties = properties;
        this.cacheDao = cacheDao;
        this.verdictsDao = verdictsDao;
        this.client = client;
        this.asyncExecutor = asyncExecutor;
    }

    @Timed(value = "silicaproxy.service.extvalidation.check",
            description = "Duration of external validation check across all configured services",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<DecisionResult> checkExternalServices(
            String packageName, String version, String ecosystem) {
        Map<String, ExternalValidationServiceProperties> allServices =
                properties.externalValidation().services();

        List<Map.Entry<String, ExternalValidationServiceProperties>> enabled = allServices.entrySet()
                .stream()
                .filter(e -> e.getValue().enabled())
                .toList();

        if (enabled.isEmpty()) {
            return Optional.empty();
        }

        List<Map.Entry<String, ExternalValidationServiceProperties>> syncServices = enabled.stream()
                .filter(e -> "sync".equalsIgnoreCase(e.getValue().mode()))
                .toList();

        List<Map.Entry<String, ExternalValidationServiceProperties>> asyncServices = enabled.stream()
                .filter(e -> "async".equalsIgnoreCase(e.getValue().mode()))
                .toList();

        // 1. Run all SYNC services in parallel, wait for all results
        List<ServiceOutcome> syncOutcomes = runSyncServicesInParallel(
                syncServices, packageName, version, ecosystem);

        boolean syncBlocked = syncOutcomes.stream().anyMatch(o -> o == ServiceOutcome.BLOCK
                || o == ServiceOutcome.PENDING_CLOSED);

        // 2. Trigger ASYNC services — always if all sync ALLOW, conditionally if sync blocked
        boolean triggerAsync = !syncBlocked
                || properties.externalValidation().triggerAsyncOnSyncBlock();

        if (triggerAsync) {
            asyncServices.forEach(e -> asyncExecutor.execute(() ->
                    triggerAsyncService(e.getKey(), e.getValue(), packageName, version, ecosystem)));
        }

        // 3. Collect async state from cache (already-pending or already-resolved)
        List<ServiceOutcome> asyncOutcomes = asyncServices.stream()
                .map(e -> checkAsyncCacheState(e.getKey(), e.getValue(), packageName, version, ecosystem))
                .toList();

        // 4. Aggregate outcomes (most restrictive wins across blocking services)
        List<ServiceOutcome> allOutcomes = new ArrayList<>(syncOutcomes);
        allOutcomes.addAll(asyncOutcomes);

        boolean anyBlock = allOutcomes.stream()
                .anyMatch(o -> o == ServiceOutcome.BLOCK || o == ServiceOutcome.PENDING_CLOSED);

        if (anyBlock) {
            String reason = buildBlockReason(enabled, packageName, version, ecosystem);
            return Optional.of(new DecisionResult("EXTERNAL_VALIDATION", "BLOCK", reason));
        }

        return Optional.of(new DecisionResult("EXTERNAL_VALIDATION", "ALLOW",
                "All external validation services allowed this package."));
    }

    // Process callback from an async external service.
    // Returns true if the token was found and processed, false if unknown or already resolved.
    public boolean processCallback(UUID callbackToken, String verdict, @Nullable String reason) {
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByCallbackToken(callbackToken);
        if (entry.isEmpty()) {
            return false;
        }
        ExternalValidationCacheEntry e = entry.get();
        if (!"PENDING".equals(e.status())) {
            return false;
        }

        if (BLOCKED.equalsIgnoreCase(verdict)) {
            // Permanent verdict — remove from cache, write to verdicts table
            cacheDao.deleteByToken(callbackToken);
            verdictsDao.save(e.serviceName(), e.packageName(), e.ecosystem(), e.packageVersion(), reason);
            return true;
        }
        if (ALLOWED.equalsIgnoreCase(verdict)) {
            ExternalValidationServiceProperties props =
                    properties.externalValidation().services().get(e.serviceName());
            int cacheTtlMinutes = props != null ? props.cacheTtlMinutes() : 60;
            Instant cacheExpiry = Instant.now().plus(cacheTtlMinutes, ChronoUnit.MINUTES);
            return cacheDao.updateToAllowedByToken(callbackToken, reason, cacheExpiry);
        }
        return false;
    }

    // --- Private helpers ---

    private List<ServiceOutcome> runSyncServicesInParallel(
            List<Map.Entry<String, ExternalValidationServiceProperties>> services,
            String packageName, String version, String ecosystem) {
        List<CompletableFuture<ServiceOutcome>> futures = services.stream()
                .map(e -> CompletableFuture.supplyAsync(
                        () -> checkSyncService(e.getKey(), e.getValue(), packageName, version, ecosystem),
                        asyncExecutor))
                .toList();
        return futures.stream()
                .map(CompletableFuture::join)
                .toList();
    }

    private ServiceOutcome checkSyncService(
            String serviceName, ExternalValidationServiceProperties props,
            String packageName, String version, String ecosystem) {
        // Permanent block check first
        if (verdictsDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version).isPresent()) {
            return props.blocking() ? ServiceOutcome.BLOCK : ServiceOutcome.ALLOW;
        }

        // Cache check
        Optional<ExternalValidationCacheEntry> cached =
                cacheDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version);
        if (cached.isPresent()) {
            ExternalValidationCacheEntry entry = cached.get();
            if (ALLOWED.equals(entry.status()) && entry.expiresAt().isAfter(Instant.now())) {
                return ServiceOutcome.ALLOW;
            }
            if ("PENDING".equals(entry.status()) && entry.expiresAt().isAfter(Instant.now())) {
                // Another concurrent check in progress — apply fail-open/closed without re-scanning
                return props.failOpen() ? ServiceOutcome.PENDING_OPEN : ServiceOutcome.PENDING_CLOSED;
            }
            // TIMEOUT or expired → fall through to re-scan
        }

        // Make sync call
        Instant pendingExpiry = Instant.now().plus(Math.max(props.timeoutSeconds() * 2L, 30), ChronoUnit.SECONDS);
        cacheDao.upsertPendingSync(serviceName, packageName, ecosystem, version, pendingExpiry);

        ExternalValidationResult result = client.callSync(
                props.url(), props.apiKey(), packageName, version, ecosystem);

        if (result == null) {
            // Error or timeout
            cacheDao.updateToTimeout(serviceName, packageName, ecosystem, version);
            LOG.debug("External validation sync call to {} failed for {}/{} ({})",
                    serviceName, ecosystem, packageName, version);
            return props.failOpen() ? ServiceOutcome.PENDING_OPEN : ServiceOutcome.PENDING_CLOSED;
        }

        if (BLOCKED.equalsIgnoreCase(result.verdict())) {
            cacheDao.updateToTimeout(serviceName, packageName, ecosystem, version);
            if (props.blocking()) {
                verdictsDao.save(serviceName, packageName, ecosystem, version, result.reason());
                return ServiceOutcome.BLOCK;
            } else {
                // Non-blocking: record informational verdict but treat as ALLOW
                verdictsDao.save(serviceName, packageName, ecosystem, version, result.reason());
                return ServiceOutcome.ALLOW;
            }
        }

        // ALLOWED
        Instant cacheExpiry = Instant.now().plus(props.cacheTtlMinutes(), ChronoUnit.MINUTES);
        cacheDao.updateToAllowed(serviceName, packageName, ecosystem, version, result.reason(), cacheExpiry);
        return ServiceOutcome.ALLOW;
    }

    private void triggerAsyncService(
            String serviceName, ExternalValidationServiceProperties props,
            String packageName, String version, String ecosystem) {
        // Already in process (valid PENDING or ALLOWED) — no need to re-trigger
        if (verdictsDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version).isPresent()) {
            return;
        }
        Optional<ExternalValidationCacheEntry> cached =
                cacheDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version);
        if (cached.isPresent()) {
            ExternalValidationCacheEntry entry = cached.get();
            boolean validPending = "PENDING".equals(entry.status()) && entry.expiresAt().isAfter(Instant.now());
            boolean validAllowed = "ALLOWED".equals(entry.status()) && entry.expiresAt().isAfter(Instant.now());
            if (validPending || validAllowed) {
                return;
            }
        }

        UUID token = UUID.randomUUID();
        int pendingTtlMinutes = props.pendingTtlMinutes() > 0 ? props.pendingTtlMinutes() : 30;
        Instant pendingExpiry = Instant.now().plus(pendingTtlMinutes, ChronoUnit.MINUTES);
        cacheDao.upsertPendingAsync(token, serviceName, packageName, ecosystem, version, pendingExpiry);

        String callbackUrl = buildCallbackUrl(token);
        boolean sent = client.callAsync(props.url(), props.apiKey(), packageName, version, ecosystem, callbackUrl);
        if (!sent) {
            cacheDao.updateToTimeout(serviceName, packageName, ecosystem, version);
        }
    }

    // Check cache/verdicts state for an async service without triggering a new call.
    // Used when async services run AFTER sync (fire-and-forget already done).
    private ServiceOutcome checkAsyncCacheState(
            String serviceName, ExternalValidationServiceProperties props,
            String packageName, String version, String ecosystem) {
        if (verdictsDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version).isPresent()) {
            return props.blocking() ? ServiceOutcome.BLOCK : ServiceOutcome.ALLOW;
        }
        Optional<ExternalValidationCacheEntry> cached =
                cacheDao.findByServiceAndPackage(serviceName, packageName, ecosystem, version);
        if (cached.isPresent()) {
            ExternalValidationCacheEntry entry = cached.get();
            if (ALLOWED.equals(entry.status()) && entry.expiresAt().isAfter(Instant.now())) {
                return ServiceOutcome.ALLOW;
            }
            if ("PENDING".equals(entry.status()) && entry.expiresAt().isAfter(Instant.now())) {
                return props.failOpen() ? ServiceOutcome.PENDING_OPEN : ServiceOutcome.PENDING_CLOSED;
            }
        }
        // No entry or expired — new async call was just triggered; apply fail-open/fail-closed
        return props.failOpen() ? ServiceOutcome.PENDING_OPEN : ServiceOutcome.PENDING_CLOSED;
    }

    private String buildCallbackUrl(UUID token) {
        String base = properties.externalValidation().callbackBaseUrl();
        if (base == null || base.isBlank()) {
            base = "";
        }
        return base + "/external-validation/callback/" + token;
    }

    private String buildBlockReason(
            List<Map.Entry<String, ExternalValidationServiceProperties>> services,
            String packageName, String version, String ecosystem) {
        // Look up the blocking verdict/reason from the verdicts table or cache
        for (var entry : services) {
            var verdict = verdictsDao.findByServiceAndPackage(
                    entry.getKey(), packageName, ecosystem, version);
            if (verdict.isPresent() && verdict.get().reason() != null) {
                return verdict.get().reason();
            }
        }
        return "Package blocked by external validation service.";
    }

    private enum ServiceOutcome {
        BLOCK,
        ALLOW,
        PENDING_OPEN,
        PENDING_CLOSED
    }
}
