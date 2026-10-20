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


package com.silicaproxy.dao.client;

import com.silicaproxy.model.dto.AdvisoryFinding;
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.properties.SilicaProxyProperties;
import com.silicaproxy.service.vulnerability.AdvisorySeverityScorer;
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Locale;
import java.util.List;
import java.util.Map;

/**
 * Queries the public Google OSV API (POST {@code /v1/query}) for a package/version missing 
 * from local tables. Called by {@code SecurityService} at the end of the fallback chain (after 
 * quarantine/deprecation), only if {@code api-fallback.osv.enabled} is active ; the 
 * result is then cached for 24h in {@code api_cache}.
 */
@Component
@NullMarked
public class OsvClient {

    private static final Logger LOG = LoggerFactory.getLogger(OsvClient.class);

    private final RestClient restClient;
    private final SilicaProxyProperties properties;
    private final AdvisorySeverityScorer severityScorer;

    public OsvClient(
            SilicaProxyProperties properties,
            @Qualifier("securityApisRequestFactory") ClientHttpRequestFactory securityApisRequestFactory,
            com.silicaproxy.config.SsrfInterceptor ssrfInterceptor,
            AdvisorySeverityScorer severityScorer) {
        this.properties = properties;
        this.severityScorer = severityScorer;

        this.restClient = RestClient.builder()
                .requestFactory(securityApisRequestFactory)
                .requestInterceptor(ssrfInterceptor)
                .build();
    }

    @Timed(value = "silicaproxy.dao.osv.checkvulnerability",
            description = "Duration of calling OSV API to check vulnerabilities of a package",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public ApiCheckResult checkVulnerability(String packageName, String version, String ecosystem) {
        SilicaProxyProperties.ApiFallbackProperties osvProps = properties.apiFallback().get("osv");
        if (osvProps == null || !osvProps.enabled()) {
            return new ApiCheckResult(false, 0, 0, 0, null);
        }

        String url = osvProps.url();
        Map<String, Object> request = Map.of(
            "package", Map.of("name", packageName, "ecosystem", mapEcosystemToOsv(ecosystem)),
            "version", version
        );

        long start = System.nanoTime();
        try {
            JsonNode response = restClient.post()
                    .uri(url)
                    .body(request)
                    .retrieve()
                    .body(JsonNode.class);

            long responseTimeMs = (System.nanoTime() - start) / 1_000_000;
            if (response == null) {
                return new ApiCheckResult(false, 0, 200, responseTimeMs, null);
            }
            // Every reported advisory, scored like the ingested ones : the severity threshold is
            // applied afterwards (SeverityPolicy), on par with the local tables.
            List<AdvisoryFinding> findings = new ArrayList<>();
            for (JsonNode vuln : response.path("vulns")) {
                String id = vuln.path("id").asString("");
                if (!id.isEmpty()) {
                    findings.add(new AdvisoryFinding(id, AdvisorySeverityScorer.relatedIds(vuln),
                            severityScorer.score(vuln)));
                }
            }
            return ApiCheckResult.ofFindings(200, responseTimeMs, findings);
        } catch (HttpStatusCodeException e) {
            long responseTimeMs = (System.nanoTime() - start) / 1_000_000;
            LOG.warn("HTTP failure {} from OSV API for {}/{} ({})", e.getStatusCode().value(),
                    ecosystem, packageName, version);
            return new ApiCheckResult(false, 0, e.getStatusCode().value(), responseTimeMs, e.getMessage());
        } catch (Exception e) {
            long responseTimeMs = (System.nanoTime() - start) / 1_000_000;
            LOG.warn("Failure of fallback OSV API call for {}/{} ({}) : {}",
                    ecosystem, packageName, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Details of OSV API call error", e);
            }
            return new ApiCheckResult(false, 0, 0, responseTimeMs, e.getMessage());
        }
    }


    private String mapEcosystemToOsv(String ecosystem) {
        return switch (ecosystem.toLowerCase(Locale.ROOT)) {
            case "npm" -> "npm";
            case "pypi" -> "PyPI";
            case "maven" -> "Maven";
            default -> ecosystem;
        };
    }
}
