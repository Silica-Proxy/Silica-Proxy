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

import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Client for the public Google deps.dev API (Open Source Insights), used as a fallback source 
 * in the fallback chain . Queries
 * GetVersion (`/systems/{system}/packages/{name}/versions/{version}`) whose response contains
 * a non-empty `advisoryKeys` field if the version is affected by a known OSV advisory.
 */
@Component
@NullMarked
public class DepsDevClient {

    private static final Logger LOG = LoggerFactory.getLogger(DepsDevClient.class);

    private final RestClient restClient;
    private final SilicaProxyProperties properties;

    public DepsDevClient(
            SilicaProxyProperties properties,
            @Qualifier("securityApisRequestFactory") ClientHttpRequestFactory securityApisRequestFactory,
            com.silicaproxy.config.SsrfInterceptor ssrfInterceptor) {
        this.properties = properties;
        this.restClient = RestClient.builder()
                .requestFactory(securityApisRequestFactory)
                .requestInterceptor(ssrfInterceptor)
                .build();
    }

    @SuppressWarnings("unchecked")
    public ApiCheckResult checkVulnerability(String packageName, String version, String ecosystem) {
        SilicaProxyProperties.ApiFallbackProperties depsDevProps = properties.apiFallback().get("deps-dev");
        if (depsDevProps == null || !depsDevProps.enabled()) {
            return new ApiCheckResult(false, 0, 0, 0, null);
        }

        String baseUrl = depsDevProps.url().endsWith("/")
                ? depsDevProps.url().substring(0, depsDevProps.url().length() - 1)
                : depsDevProps.url();
        String url = baseUrl + "/systems/" + mapEcosystemToDepsDevSystem(ecosystem)
                + "/packages/" + URLEncoder.encode(packageName, StandardCharsets.UTF_8)
                + "/versions/" + URLEncoder.encode(version, StandardCharsets.UTF_8);

        long start = System.nanoTime();
        try {
            Map<String, Object> response = restClient.get()
                    .uri(url)
                    .retrieve()
                    .body(Map.class);

            long responseTimeMs = (System.nanoTime() - start) / 1_000_000;
            if (response == null) {
                return new ApiCheckResult(false, 0, 200, responseTimeMs, null);
            }
            List<?> advisoryKeys = (List<?>) response.get("advisoryKeys");
            int vulnCount = advisoryKeys != null ? advisoryKeys.size() : 0;
            return new ApiCheckResult(vulnCount > 0, vulnCount, 200, responseTimeMs, null);
        } catch (HttpStatusCodeException e) {
            long responseTimeMs = (System.nanoTime() - start) / 1_000_000;
            LOG.warn("HTTP failure {} from deps.dev API for {}/{} ({})", e.getStatusCode().value(),
                    ecosystem, packageName, version);
            return new ApiCheckResult(false, 0, e.getStatusCode().value(), responseTimeMs, e.getMessage());
        } catch (Exception e) {
            long responseTimeMs = (System.nanoTime() - start) / 1_000_000;
            LOG.warn("Failure of deps.dev fallback API call for {}/{} ({}) : {}",
                    ecosystem, packageName, version, e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Details of deps.dev API call error", e);
            }
            return new ApiCheckResult(false, 0, 0, responseTimeMs, e.getMessage());
        }
    }

    private String mapEcosystemToDepsDevSystem(String ecosystem) {
        return switch (ecosystem.toLowerCase()) {
            case "npm" -> "NPM";
            case "pypi" -> "PYPI";
            case "maven" -> "MAVEN";
            default -> ecosystem.toUpperCase();
        };
    }
}
