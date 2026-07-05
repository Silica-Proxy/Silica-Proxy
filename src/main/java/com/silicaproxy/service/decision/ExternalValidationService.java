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

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.client.ExternalValidationClient;
import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import com.silicaproxy.model.entity.ExternalValidationVerdictEntry;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.properties.SilicaProxyProperties.ExternalValidationServiceProperties;
import io.micrometer.core.annotation.Timed;
import jakarta.annotation.PostConstruct;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

@Service
@NullMarked
public class ExternalValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalValidationService.class);

    private final SilicaProxyProperties properties;
    private final ExternalValidationCacheDao cacheDao;
    private final ExternalValidationVerdictsDao verdictsDao;
    private final ExternalValidationClient client;
    private final Executor asyncExecutor;
    private final ExternalValidationMetrics metrics;

    public ExternalValidationService(
            SilicaProxyProperties properties,
            ExternalValidationCacheDao cacheDao,
            ExternalValidationVerdictsDao verdictsDao,
            ExternalValidationClient client,
            @Qualifier("externalValidationExecutor") Executor asyncExecutor,
            ExternalValidationMetrics metrics) {
        this.properties = properties;
        this.cacheDao = cacheDao;
        this.verdictsDao = verdictsDao;
        this.client = client;
        this.asyncExecutor = asyncExecutor;
        this.metrics = metrics;
    }

    @PostConstruct
    void logConfiguredServices() {
        Map<String, ExternalValidationServiceProperties> services = properties.externalValidation().services();
        if (services.isEmpty()) {
            LOG.info("External validation: no service configured.");
            return;
        }
        services.forEach((name, props) -> LOG.info(
                "External validation service '{}' loaded: enabled={}, mode={}, url={}, blocking={}, "
                        + "failOpen={}, timeoutSeconds={}, cacheTtlMinutes={}",
                name, props.enabled(), props.mode(), props.url(), props.blocking(),
                props.failOpen(), props.timeoutSeconds(), props.cacheTtlMinutes()));
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

        List<Map.Entry<String, ExternalValidationServiceProperties>> asyncServices = enabled.stream()
                .filter(e -> Metrics.TYPE_ASYNC.equalsIgnoreCase(e.getValue().mode()))
                .toList();

        // Short-circuit: a permanent BLOCK verdict from any blocking service already
        // seals the aggregate result (most restrictive wins), so skip every SYNC network
        // call entirely instead of re-validating with the other configured services.
        // ASYNC services are still fire-and-forget triggered when trigger-async-on-sync-block
        // is enabled, so that flag's documented purpose (collecting every scanner's opinion
        // for the audit trail, even on an already-blocked package) keeps being honored.
        Optional<DecisionResult> permanentBlock =
                checkPermanentBlock(enabled, packageName, version, ecosystem);
        if (permanentBlock.isPresent()) {
            metrics.recordBlockReasonMetric(Metrics.REASON_VERDICT);
            if (properties.externalValidation().triggerAsyncOnSyncBlock()) {
                asyncServices.forEach(e -> asyncExecutor.execute(() ->
                        triggerAsyncService(e.getKey(), e.getValue(), packageName, version, ecosystem)));
            }
            return permanentBlock;
        }

        List<Map.Entry<String, ExternalValidationServiceProperties>> syncServices = enabled.stream()
                .filter(e -> Metrics.TYPE_SYNC.equalsIgnoreCase(e.getValue().mode()))
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
            boolean realVerdict = allOutcomes.stream().anyMatch(o -> o == ServiceOutcome.BLOCK);
            metrics.recordBlockReasonMetric(realVerdict ? Metrics.REASON_VERDICT : Metrics.REASON_FAIL_CLOSED);
            String reason = buildBlockReason(enabled, packageName, version, ecosystem);
            return Optional.of(new DecisionResult("EXTERNAL_VALIDATION", "BLOCK", reason));
        }

        return Optional.of(new DecisionResult("EXTERNAL_VALIDATION", "ALLOW",
                "All external validation services allowed this package."));
    }

    // Process callback from an async external service. The api-key check is only enforced
    // when the service has one configured (services.<name>.api-key) — it stays optional so
    // existing integrations without a configured key keep working unchanged.
    public CallbackResult processCallback(
            UUID callbackToken, String verdict, @Nullable String reason, @Nullable String providedApiKey) {
        Optional<ExternalValidationCacheEntry> entry = cacheDao.findByCallbackToken(callbackToken);
        if (entry.isEmpty()) {
            // Token doesn't exist at all -- serviceName is unknowable at this point.
            metrics.recordCallbackMetric(Metrics.SERVICE_UNKNOWN, CallbackResult.NOT_FOUND.name());
            return CallbackResult.NOT_FOUND;
        }
        ExternalValidationCacheEntry e = entry.get();
        if (!"PENDING".equals(e.status())) {
            metrics.recordCallbackMetric(e.serviceName(), CallbackResult.NOT_FOUND.name());
            return CallbackResult.NOT_FOUND;
        }

        ExternalValidationServiceProperties props =
                properties.externalValidation().services().get(e.serviceName());
        String expectedApiKey = props != null ? props.apiKey() : null;
        if (expectedApiKey != null && !expectedApiKey.isBlank()
                && !constantTimeEquals(expectedApiKey, providedApiKey)) {
            LOG.warn("External validation callback for service {} rejected: missing or invalid API key",
                    e.serviceName());
            metrics.recordCallbackMetric(e.serviceName(), CallbackResult.UNAUTHORIZED.name());
            return CallbackResult.UNAUTHORIZED;
        }

        LOG.info("External validation callback received from {} for {}/{}@{}: verdict={}, reason={}",
                e.serviceName(), e.ecosystem(), e.packageName(), e.packageVersion(), verdict, reason);

        if (Metrics.BLOCKED.equalsIgnoreCase(verdict)) {
            // Permanent verdict — remove from cache (atomically, guarded by status='PENDING'
            // so a duplicate/racing callback delivery for the same token can't double-process
            // it), then write to verdicts table.
            if (!cacheDao.deleteByToken(callbackToken)) {
                metrics.recordCallbackMetric(e.serviceName(), CallbackResult.NOT_FOUND.name());
                return CallbackResult.NOT_FOUND;
            }
            verdictsDao.save(e.serviceName(), e.packageName(), e.ecosystem(), e.packageVersion(), reason);
            metrics.recordExternalValidationCallMetric(e.serviceName(), Metrics.TYPE_ASYNC, Metrics.BLOCKED);
            metrics.recordCallbackMetric(e.serviceName(), CallbackResult.PROCESSED.name());
            return CallbackResult.PROCESSED;
        }
        if (Metrics.ALLOWED.equalsIgnoreCase(verdict)) {
            int cacheTtlMinutes = props != null ? props.cacheTtlMinutes() : 60;
            Instant cacheExpiry = Instant.now().plus(cacheTtlMinutes, ChronoUnit.MINUTES);
            if (!cacheDao.updateToAllowedByToken(callbackToken, reason, cacheExpiry)) {
                metrics.recordCallbackMetric(e.serviceName(), CallbackResult.NOT_FOUND.name());
                return CallbackResult.NOT_FOUND;
            }
            metrics.recordExternalValidationCallMetric(e.serviceName(), Metrics.TYPE_ASYNC, Metrics.ALLOWED);
            metrics.recordCallbackMetric(e.serviceName(), CallbackResult.PROCESSED.name());
            return CallbackResult.PROCESSED;
        }
        metrics.recordCallbackMetric(e.serviceName(), CallbackResult.NOT_FOUND.name());
        return CallbackResult.NOT_FOUND;
    }

    private static boolean constantTimeEquals(String expected, @Nullable String actual) {
        if (actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    public enum CallbackResult {
        PROCESSED,
        NOT_FOUND,
        UNAUTHORIZED
    }

    // --- Private helpers ---

    private Optional<DecisionResult> checkPermanentBlock(
            List<Map.Entry<String, ExternalValidationServiceProperties>> enabledServices,
            String packageName, String version, String ecosystem) {
        List<ExternalValidationVerdictEntry> verdicts =
                verdictsDao.findAllByPackage(packageName, ecosystem, version);
        if (verdicts.isEmpty()) {
            return Optional.empty();
        }
        Map<String, ExternalValidationServiceProperties> enabledByName = enabledServices.stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        for (ExternalValidationVerdictEntry verdict : verdicts) {
            ExternalValidationServiceProperties props = enabledByName.get(verdict.serviceName());
            if (props != null && props.blocking()) {
                String reason = verdict.reason() != null
                        ? verdict.reason() : "Package blocked by external validation service.";
                return Optional.of(new DecisionResult("EXTERNAL_VALIDATION", "BLOCK", reason));
            }
        }
        return Optional.empty();
    }

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
            if (Metrics.ALLOWED.equals(entry.status()) && entry.expiresAt().isAfter(Instant.now())) {
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

        ExternalValidationClient.ExternalValidationResult result = client.callSync(
                props.url(), props.apiKey(), packageName, version, ecosystem);

        return resolveSyncResult(serviceName, props, packageName, version, ecosystem, result);
    }

    private ServiceOutcome resolveSyncResult(
            String serviceName, ExternalValidationServiceProperties props,
            String packageName, String version, String ecosystem,
            ExternalValidationClient.@Nullable ExternalValidationResult result) {
        if (result == null) {
            // Error or timeout
            metrics.recordExternalValidationCallMetric(serviceName, Metrics.TYPE_SYNC, Metrics.RESULT_ERROR);
            cacheDao.updateToTimeout(serviceName, packageName, ecosystem, version);
            LOG.debug("External validation sync call to {} failed for {}/{} ({})",
                    serviceName, ecosystem, packageName, version);
            return props.failOpen() ? ServiceOutcome.PENDING_OPEN : ServiceOutcome.PENDING_CLOSED;
        }

        if (Metrics.BLOCKED.equalsIgnoreCase(result.verdict())) {
            metrics.recordExternalValidationCallMetric(serviceName, Metrics.TYPE_SYNC, Metrics.BLOCKED);
            cacheDao.updateToTimeout(serviceName, packageName, ecosystem, version);
            // Recorded either way — blocking=false only changes whether it's enforced
            verdictsDao.save(serviceName, packageName, ecosystem, version, result.reason());
            return props.blocking() ? ServiceOutcome.BLOCK : ServiceOutcome.ALLOW;
        }

        if (!Metrics.ALLOWED.equalsIgnoreCase(result.verdict())) {
            // Malformed/unexpected verdict (missing field, typo, unknown value) — treat
            // like a transport error rather than silently allowing, so fail-open/fail-closed
            // is honored instead of being bypassed by a non-conformant response body.
            metrics.recordExternalValidationCallMetric(serviceName, Metrics.TYPE_SYNC, Metrics.RESULT_UNKNOWN_VERDICT);
            cacheDao.updateToTimeout(serviceName, packageName, ecosystem, version);
            LOG.warn("External validation service {} returned unexpected verdict '{}' for {}/{} ({}) "
                            + "— applying failOpen={} policy",
                    serviceName, result.verdict(), ecosystem, packageName, version, props.failOpen());
            return props.failOpen() ? ServiceOutcome.PENDING_OPEN : ServiceOutcome.PENDING_CLOSED;
        }

        // ALLOWED
        metrics.recordExternalValidationCallMetric(serviceName, Metrics.TYPE_SYNC, Metrics.ALLOWED);
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
            boolean validAllowed = Metrics.ALLOWED.equals(entry.status()) && entry.expiresAt().isAfter(Instant.now());
            if (validPending || validAllowed) {
                return;
            }
        }

        UUID token = UUID.randomUUID();
        Instant pendingExpiry = Instant.now().plus(props.pendingTtlMinutes(), ChronoUnit.MINUTES);
        cacheDao.upsertPendingAsync(token, serviceName, packageName, ecosystem, version, pendingExpiry);

        String callbackUrl = buildCallbackUrl(token);
        boolean sent = client.callAsync(props.url(), props.apiKey(), packageName, version, ecosystem, callbackUrl);
        metrics.recordExternalValidationCallMetric(serviceName, Metrics.TYPE_ASYNC, sent ? Metrics.RESULT_TRIGGERED : Metrics.RESULT_TRIGGER_ERROR);
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
            if (Metrics.ALLOWED.equals(entry.status()) && entry.expiresAt().isAfter(Instant.now())) {
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
        // Only a service configured as blocking=true can be the actual cause of the BLOCK —
        // a non-blocking (informational) service's stored verdict must not be misattributed
        // as the reason, even if it happens to have one recorded for this package.
        for (Map.Entry<String, ExternalValidationServiceProperties> entry : services) {
            if (!entry.getValue().blocking()) {
                continue;
            }
            Optional<ExternalValidationVerdictEntry> verdict = verdictsDao.findByServiceAndPackage(
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
