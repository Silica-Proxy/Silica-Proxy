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
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.RangeCandidate;
import com.silicaproxy.service.vulnerability.version.OsvRangeEvaluator;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.Optional;

/**
 * Local (database only, no network) step of {@code SecurityService.getDecision()} : the single
 * {@code UNION ALL} query of {@link DecisionDao#evaluateDecision}, then the OSV ranges of
 * {@code public_vulnerabilities} (npm advisories list no affected version, only SEMVER ranges)
 * that this query cannot match, evaluated at the public vulnerability priority.
 */
@Service
@NullMarked
public class LocalDecisionEvaluator {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalDecisionEvaluator.class);

    private final DecisionDao decisionDao;
    private final ObjectMapper objectMapper;

    public LocalDecisionEvaluator(DecisionDao decisionDao, ObjectMapper objectMapper) {
        this.decisionDao = decisionDao;
        this.objectMapper = objectMapper;
    }

    public Optional<DecisionResult> evaluate(String packageName, String version, String ecosystem, double minCvss) {
        Optional<DecisionResult> sqlDecision = decisionDao.evaluateDecision(packageName, version, ecosystem, minCvss);
        // P1 (company policy) and P2 (enumerated public vulnerability) are final ; an api_cache
        // (P3) verdict is not yet : OSV ranges (P2 rank) must outrank it.
        if (sqlDecision.isPresent() && !"API_CACHE".equals(sqlDecision.get().sourceType())) {
            return sqlDecision;
        }
        Optional<DecisionResult> rangeDecision = matchRanges(packageName, version, ecosystem, minCvss);
        return rangeDecision.isPresent() ? rangeDecision : sqlDecision;
    }

    // Builds the same DecisionResult the PRIORITY 2 SQL branch of DecisionDao.evaluateDecision()
    // would have produced for an enumerated version.
    private Optional<DecisionResult> matchRanges(String packageName, String version, String ecosystem, double minCvss) {
        for (RangeCandidate candidate : decisionDao.findRangeCandidates(packageName, ecosystem, minCvss)) {
            JsonNode ranges;
            try {
                ranges = objectMapper.readTree(candidate.rangesJson());
            } catch (RuntimeException e) {
                LOGGER.warn("Unreadable affected_ranges for advisory {} ({}), row ignored",
                        candidate.id(), packageName, e);
                continue;
            }
            if (OsvRangeEvaluator.isAffected(ecosystem, version, ranges)) {
                String sourceType = candidate.id().startsWith("MAL-") || "OPENSSF".equals(candidate.source())
                        ? "PUBLIC_VULN_MALWARE" : "PUBLIC_VULN";
                return Optional.of(new DecisionResult(sourceType, "BLOCK", candidate.summary()));
            }
        }
        return Optional.empty();
    }
}
