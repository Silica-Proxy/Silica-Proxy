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

import com.silicaproxy.dao.client.ProxyStreamClient;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.UrlParserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URI;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Main entry point of the proxy  : intercepts all {@code GET /**} requests
 * forwarded by the artifacts repository (or via the CONNECT tunnel from {@code LoomProxyServer}), 
 * extracts package/version/ecosystem from the URL, queries {@link SecurityService} for the decision, 
 * then either streams the download (ALLOW/WHITELIST) or returns a detailed 403 RFC 7807 
 * response (BLOCK/BLACKLIST). Called at each dependency resolution by package managers 
 * (npm, pip, Maven) ; each call also triggers an asynchronous audit.
 */
@RestController
@NullMarked
public class ProxyController {

    private static final Logger LOG = LoggerFactory.getLogger(ProxyController.class);

    private final SecurityService securityService;
    private final AuditLogService auditLogService;
    private final ProxyStreamClient proxyStreamClient;
    private final UrlParserService urlParserService;
    private final MeterRegistry meterRegistry;

    public ProxyController(
            SecurityService securityService,
            AuditLogService auditLogService,
            ProxyStreamClient proxyStreamClient,
            UrlParserService urlParserService,
            MeterRegistry meterRegistry) {
        this.securityService = securityService;
        this.auditLogService = auditLogService;
        this.proxyStreamClient = proxyStreamClient;
        this.urlParserService = urlParserService;
        this.meterRegistry = meterRegistry;
    }

    @GetMapping("/**")
    @Timed(value = "silicaproxy.controller.requests",
            description = "Processing duration of the proxy request by the Controller",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void proxyRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        long startTime = System.currentTimeMillis();
        
        String requestUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();
        String fullUrl = queryString != null ? requestUrl + "?" + queryString : requestUrl;

        LOG.info("Intercepted request : {} {}", request.getMethod(), fullUrl);

        // Exclude actuator endpoints from being proxied if they fall through
        if (request.getRequestURI().startsWith("/actuator/")) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        // Ensure we only proxy HTTP/HTTPS
        if (!requestUrl.startsWith("http")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Only absolute HTTP/HTTPS requests are supported by this proxy.");
            return;
        }

        UrlParserService.ParsedPackage parsed = urlParserService.parseUrl(fullUrl);
        String packageName = parsed.packageName();
        String version = parsed.version();
        String ecosystem = parsed.ecosystem();

        if (ecosystem.equals("unknown") || packageName.equals("unknown") || version.equals("unknown")) {
            String forwardUrl = convertToHttpsIfNeeded(fullUrl);
            LOG.warn("Unknown ecosystem or direct resource. Bypassing security control for : {}", forwardUrl);
            forwardRequest(forwardUrl, request, response);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Package detected : ecosystem={}, package={}, version={}", ecosystem, packageName, version);
        }

        DecisionResult decision = securityService.getDecision(packageName, version, ecosystem);
        long executionTimeMs = System.currentTimeMillis() - startTime;
        boolean blocked = "BLOCK".equals(decision.result()) || "BLACKLIST".equals(decision.result());
        Timer.builder("silicaproxy.controller.security.overhead")
                .description("Duration of security check only (excluding binary streaming)")
                .tag("decision", blocked ? "block" : "allow")
                .publishPercentiles(0.5, 0.9, 0.95, 0.99)
                .register(meterRegistry)
                .record(Duration.ofMillis(executionTimeMs));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Final decision for {}/{} (ecosystem={}) : RESULT={} (Source={}, Reason: {}) [Calculated in {}ms]",
                    packageName, version, ecosystem, decision.result(), decision.sourceType(), decision.reason(), executionTimeMs);
        }

        auditLogService.logAudit(
                packageName,
                version,
                ecosystem,
                decision.sourceType(),
                decision.result(),
                decision.reason(),
                (int) executionTimeMs
        );

        if (blocked) {
            LOG.warn("Request BLOCKED for {}/{} (ecosystem={}, step={}) : {}",
                    packageName, version, ecosystem, decision.sourceType(), decision.reason());
            sendProblemDetail(response, packageName, version, ecosystem, decision);
            return;
        }

        String forwardUrl = convertToHttpsIfNeeded(fullUrl);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request ALLOWED : Forwarding to {}", forwardUrl);
        }
        forwardRequest(forwardUrl, request, response);
    }

    private void forwardRequest(String fullUrl, HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpHeaders headers = extractHeaders(request);
        
        try {
            ProxyStreamClient.StreamResponse streamResponse = proxyStreamClient.streamContent(fullUrl, headers);
            
            response.setStatus(streamResponse.status().value());
            
            streamResponse.headers().forEach((headerName, headerValues) -> {
                // JdkClientHttpRequestFactory (Java HttpClient) exposes HTTP/2 pseudo-headers 
                // (ex: ":status: 200") in the response map. Passing them as-is in 
                // an HTTP/1.1 response causes "Invalid header: :status" for downstream 
                // HTTP/1.1 clients (Apache HttpClient used by artifacts repositories).
                if (!headerName.equalsIgnoreCase("Transfer-Encoding") && !headerName.startsWith(":")) {
                    for (String headerValue : headerValues) {
                        response.addHeader(headerName, headerValue);
                    }
                }
            });

            if (streamResponse.body() != null) {
                // Buffer of 16 KB (default in StreamUtils.copy)
                StreamUtils.copy(streamResponse.body(), response.getOutputStream());
            }
        } catch (Exception e) {
            LOG.error("Proxy error to upstream registry when forwarding request {}", fullUrl, e);
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Proxy error to upstream registry.");
        }
    }

    private HttpHeaders extractHeaders(HttpServletRequest request) {
        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                headers.put(headerName, Collections.list(request.getHeaders(headerName)));
            }
        }
        return headers;
    }

    private void sendProblemDetail(
            HttpServletResponse response,
            String packageName,
            String version,
            String ecosystem,
            DecisionResult decision) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/problem+json");
        response.setCharacterEncoding("UTF-8");

        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, decision.reason());
        pd.setProperty("step", decision.sourceType());
        pd.setProperty("package", packageName);
        pd.setProperty("version", version);
        pd.setProperty("ecosystem", ecosystem);

        if ("REGISTRY_QUARANTINE".equals(decision.sourceType())) {
            pd.setProperty("error", "QuarantineBlocked");
        } else {
            pd.setProperty("error", "SecurityBlocked");
        }

        // We manually serialize since we are writing directly to response output stream to bypass stream forwarder
        var pdType = pd.getType();
        var pdInstance = pd.getInstance();
        String json = String.format(
                "{\"type\":\"%s\",\"title\":\"%s\",\"status\":%d,\"detail\":\"%s\","
                + "\"instance\":\"%s\",\"error\":\"%s\",\"step\":\"%s\","
                + "\"package\":\"%s\",\"version\":\"%s\",\"ecosystem\":\"%s\"}",
                pdType != null ? escapeJson(pdType.toString()) : "about:blank",
                escapeJson(pd.getTitle()),
                pd.getStatus(),
                escapeJson(pd.getDetail()),
                pdInstance != null ? escapeJson(pdInstance.toString()) : "",
                escapeJson(getPdProperty(pd, "error")),
                escapeJson(getPdProperty(pd, "step")),
                escapeJson(getPdProperty(pd, "package")),
                escapeJson(getPdProperty(pd, "version")),
                escapeJson(getPdProperty(pd, "ecosystem"))
        );

        response.getWriter().print(json);
        response.getWriter().flush();
    }

    private static String getPdProperty(ProblemDetail pd, String key) {
        Map<String, Object> props = pd.getProperties();
        if (props == null) {
            return "";
        }
        Object val = props.get(key);
        return val != null ? val.toString() : "";
    }

    private static String escapeJson(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "\\\"");
    }

    private String convertToHttpsIfNeeded(String urlString) {
        if (urlString.startsWith("http://")) {
            try {
                URI uri = URI.create(urlString);
                String host = uri.getHost();
                if (host != null && !host.equals("localhost") && !host.equals("127.0.0.1") && !host.equals("host.docker.internal")) {
                    String path = uri.getRawPath();
                    String query = uri.getRawQuery();
                    String newUrl = "https://" + host + (path != null ? path : "");
                    if (query != null) {
                        newUrl += "?" + query;
                    }
                    return newUrl;
                }
            } catch (Exception e) {
                // Ignore and return original
            }
        }
        return urlString;
    }
}
