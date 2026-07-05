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


package com.silicaproxy.service.policy;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLFactory;
import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.policy.GitOpsDao;
import com.silicaproxy.dao.client.VulnerabilityGitClient;
import com.silicaproxy.model.dto.GitOpsPolicyDto;
import com.silicaproxy.model.entity.CompanyPolicy;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.vulnerability.VulnerabilitySyncStatusService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Synchronizes governance rules ({@code company_policies}) from the internal GitOps repository.
 * Triggered either by the scheduled task {@code @Scheduled} (every
 * {@code sync-interval-minutes}, under ShedLock lock {@code gitops_sync_lock}), or
 * manually via {@code POST /api/gitops/sync/force}.
 */
@Service
@NullMarked
public class GitOpsSyncService {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitOpsSyncService.class);
    private static final String GITOPS_JOB_ID = "gitops-sync";

    // npm-style convention : 'x'/'X' is only a wildcard as a full trailing version *segment*
    // (e.g. "1.2.x", "4.X"), never as a literal character occurring elsewhere (e.g. "1.0.0-xyz"
    // must stay literal). '*' remains an unambiguous wildcard token anywhere in the string.
    private static final Pattern TRAILING_X_SEGMENT = Pattern.compile("(?i)\\.x$");

    private final SilicaProxyProperties properties;
    private final VulnerabilityGitClient gitClient;
    private final GitOpsDao gitOpsDao;
    private final ObjectMapper yamlMapper;
    private final VulnerabilitySyncStatusService syncStatusService;
    private final MeterRegistry meterRegistry;

    public GitOpsSyncService(
            SilicaProxyProperties properties,
            VulnerabilityGitClient gitClient,
            GitOpsDao gitOpsDao,
            VulnerabilitySyncStatusService syncStatusService,
            MeterRegistry meterRegistry) {
        this.properties = properties;
        this.gitClient = gitClient;
        this.gitOpsDao = gitOpsDao;
        this.syncStatusService = syncStatusService;
        this.meterRegistry = meterRegistry;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        registerFreshnessGauge();
    }

    // Reads live from sync_status (shared across all instances via the DB) instead of an
    // in-process holder: the sync runs under a distributed ShedLock, so only one instance
    // executes it at a time, and leadership can move to a different instance on the next run.
    // A locally-held "last success" timestamp would freeze forever on any instance that stops
    // winning the lock, showing a false staleness alarm when that instance happens to be the
    // one scraped by Prometheus behind the load balancer.
    private void registerFreshnessGauge() {
        Gauge.builder(Metrics.GITOPS_FRESHNESS_METRIC, this, GitOpsSyncService::secondsSinceLastSuccess)
                .description("Seconds since the last successful GitOps synchronization run (NaN if it has never succeeded)")
                .register(meterRegistry);
    }

    private double secondsSinceLastSuccess() {
        return syncStatusService.getLastEndTime(GITOPS_JOB_ID)
                .map(lastEndTime -> (double) Duration.between(lastEndTime, Instant.now()).getSeconds())
                .orElse(Double.NaN);
    }

    private void recordPoliciesMetric(String ecosystem, long count) {
        Counter.builder(Metrics.GITOPS_POLICIES_METRIC)
                .description("Total number of company_policies rows synchronized from GitOps, by ecosystem")
                .tag(Metrics.TAG_ECOSYSTEM, ecosystem)
                .register(meterRegistry)
                .increment(count);
    }

    private void recordRunMetric(String outcome) {
        Counter.builder(Metrics.GITOPS_RUNS_METRIC)
                .description("Total number of GitOps synchronization runs, by outcome")
                .tag(Metrics.TAG_OUTCOME, outcome)
                .register(meterRegistry)
                .increment();
    }

    // Run every syncIntervalMinutes minutes (expressed in milliseconds in properties, wait, it's just int minutes, we use SpEL)
    @Scheduled(fixedDelayString = "#{${silicaproxy.gitops.sync-interval-minutes} * 60000}", initialDelay = 60000)
    @SchedulerLock(name = "gitops_sync_lock", lockAtMostFor = "10m", lockAtLeastFor = "30s")
    public void syncCompanyPolicies() {
        if (!properties.gitops().enabled()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("GitOps sync is disabled.");
            }
            return;
        }

        syncStatusService.startTask(GITOPS_JOB_ID);
        Instant nextRun = Instant.now().plus(properties.gitops().syncIntervalMinutes(), ChronoUnit.MINUTES);
        LOGGER.info("Starting GitOps synchronization from {}...", properties.gitops().repositoryUrl());
        try {
            File destinationDir = Path.of(properties.gitops().directoryPath()).normalize().toAbsolutePath().toFile();
            if (!destinationDir.exists() && !destinationDir.mkdirs()) {
                LOGGER.warn("Unable to create GitOps directory : {}", destinationDir);
            }

            gitClient.syncRepository(
                    properties.gitops().repositoryUrl(),
                    destinationDir,
                    properties.gitops().cloneToken()
            );

            // Each YAML file is read and parsed only once (instead of one read for
            // counting and a second for processing), the resulting DTO being reused
            // for both steps.
            @Nullable GitOpsPolicyDto npmDto = readPolicyFile(destinationDir, "npm.yaml");
            @Nullable GitOpsPolicyDto pypiDto = readPolicyFile(destinationDir, "pypi.yaml");
            @Nullable GitOpsPolicyDto mavenDto = readPolicyFile(destinationDir, "maven.yaml");

            long totalRules = countRules(npmDto) + countRules(pypiDto) + countRules(mavenDto);
            syncStatusService.setItemsTotal(GITOPS_JOB_ID, totalRules);
            LOGGER.info("GitOps sync: {} policy rules to process across all ecosystems", totalRules);

            long processed = 0;
            processed += syncEcosystem("npm", "npm.yaml", npmDto, processed, totalRules);
            processed += syncEcosystem("pypi", "pypi.yaml", pypiDto, processed, totalRules);
            syncEcosystem("maven", "maven.yaml", mavenDto, processed, totalRules);

            LOGGER.info("GitOps synchronization completed successfully.");
            syncStatusService.completeTask(GITOPS_JOB_ID, nextRun);
            recordRunMetric(Metrics.OUTCOME_SUCCESS);
        } catch (Exception e) {
            LOGGER.error("Failed to synchronize GitOps policies", e);
            syncStatusService.failTask(GITOPS_JOB_ID, e.getMessage(), nextRun);
            recordRunMetric(Metrics.OUTCOME_FAILURE);
        }
    }

    // The GitOps Git repository is an external source : a malicious <ecosystem>.yaml file could
    // be replaced by a symbolic link pointing outside `directory-path` (to the host system).
    // We only ever build a File from one of the known ecosystem filename literals below
    // (never from the `filename` parameter directly), then additionally resolve the
    // canonical path and verify it stays under the configured directory before any reading.
    private File resolveSafeFile(File baseDir, String filename) throws IOException {
        String safeName = switch (filename) {
            case "npm.yaml" -> "npm.yaml";
            case "npm.yml" -> "npm.yml";
            case "pypi.yaml" -> "pypi.yaml";
            case "pypi.yml" -> "pypi.yml";
            case "maven.yaml" -> "maven.yaml";
            case "maven.yml" -> "maven.yml";
            default -> throw new SecurityException("Refusing to read unrecognized GitOps file: " + filename);
        };
        File file = new File(baseDir, safeName);
        Path baseCanonical = baseDir.getCanonicalFile().toPath();
        Path fileCanonical = file.getCanonicalFile().toPath();
        if (!fileCanonical.startsWith(baseCanonical)) {
            throw new SecurityException(
                    "Refusing to read GitOps file '" + safeName + "' : resolved path outside the configured directory.");
        }
        return file;
    }

    // Reads and parses a rules <ecosystem>.yaml file once ; the resulting DTO is
    // then reused both for counting (countRules) and synchronization
    // (syncEcosystem), instead of re-reading and re-parsing the same file twice.
    // Supports both .yaml and .yml extensions.
    private @Nullable GitOpsPolicyDto readPolicyFile(File baseDir, String filename) {
        File yamlFile = tryReadFile(baseDir, filename);
        if (yamlFile == null) {
            // Try alternative extension (.yml instead of .yaml or vice versa)
            String altFilename = filename.endsWith(".yaml")
                ? filename.substring(0, filename.length() - 5) + ".yml"
                : filename.substring(0, filename.length() - 4) + ".yaml";
            yamlFile = tryReadFile(baseDir, altFilename);
        }

        if (yamlFile == null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("GitOps file {} not found (tried .yaml and .yml)", filename);
            }
            return null;
        }

        try {
            return yamlMapper.readValue(yamlFile, GitOpsPolicyDto.class);
        } catch (Exception e) {
            LOGGER.error("Failed to read GitOps file {}", yamlFile.getAbsolutePath(), e);
            return null;
        }
    }

    private @Nullable File tryReadFile(File baseDir, String filename) {
        File yamlFile;
        try {
            yamlFile = resolveSafeFile(baseDir, filename);
        } catch (IOException | SecurityException e) {
            return null;
        }
        return yamlFile.exists() ? yamlFile : null;
    }

    private long countRules(@Nullable GitOpsPolicyDto dto) {
        if (dto == null) {
            return 0;
        }
        List<GitOpsPolicyDto.Rule> rules = dto.rules();
        return rules != null ? rules.size() : 0;
    }

    private long syncEcosystem(String ecosystem, String filename, @Nullable GitOpsPolicyDto dto, long processedBefore, long totalRules) {
        if (dto == null) {
            return 0;
        }

        List<CompanyPolicy> policies = new ArrayList<>();
        List<GitOpsPolicyDto.Rule> rules = dto.rules();

        if (rules != null) {
            for (GitOpsPolicyDto.Rule rule : rules) {
                String rulePackage = rule.packageName();
                String ruleVersion = rule.version();
                String ruleAction = rule.action();
                String ruleReason = rule.reason();
                if (rulePackage != null && ruleVersion != null && ruleAction != null && ruleReason != null) {
                    String sqlPattern = toSqlWildcardPattern(ruleVersion);

                    policies.add(new CompanyPolicy(
                            rulePackage,
                            ecosystem,
                            sqlPattern,
                            ruleAction.toUpperCase(),
                            ruleReason,
                            "gitops_sync"
                    ));
                } else {
                    LOGGER.warn("Skipping invalid rule in {}: {}", filename, rule);
                }
            }
        }

        gitOpsDao.replaceCompanyPolicies(ecosystem, policies);
        LOGGER.info("Synchronized {} policies for ecosystem {}", policies.size(), ecosystem);
        syncStatusService.incrementItemsProcessed(GITOPS_JOB_ID, policies.size());
        recordPoliciesMetric(ecosystem, policies.size());

        long processedNow = processedBefore + policies.size();
        if (totalRules > 0) {
            long percent = (processedNow * 100L) / totalRules;
            LOGGER.info("GitOps sync progress: {}% ({}/{})", percent, processedNow, totalRules);
        }
        return policies.size();
    }

    // Only translates a trailing '.x'/'.X' *segment* into the SQL wildcard '%' ; a literal
    // 'x'/'X' occurring anywhere else in the version string is left untouched. '*' is always
    // translated, since it's an unambiguous wildcard token with no legitimate literal use in a
    // version string.
    private String toSqlWildcardPattern(String ruleVersion) {
        String withXTranslated = TRAILING_X_SEGMENT.matcher(ruleVersion).replaceAll(".%");
        return withXTranslated.replace("*", "%");
    }

}
