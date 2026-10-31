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
import com.silicaproxy.dao.client.UpstreamThrottle;
import com.silicaproxy.model.dto.ClientIdentity;
import com.silicaproxy.model.dto.DecisionResult;
import com.silicaproxy.model.dto.DecisionSource;
import com.silicaproxy.service.audit.AuditLogService;
import com.silicaproxy.service.decision.SecurityService;
import com.silicaproxy.service.interception.HttpsUpgradePolicy;
import com.silicaproxy.service.interception.NpmPackumentIndex;
import com.silicaproxy.service.interception.PackageIdentificationService;
import com.silicaproxy.service.interception.PackageIdentificationService.Identification;
import com.silicaproxy.service.interception.PackageIdentificationService.Outcome;
import com.silicaproxy.service.interception.ChecksumVerifyingRelay;
import com.silicaproxy.service.interception.ChecksumVerifyingRelay.ChecksumMismatchException;
import com.silicaproxy.service.interception.ClientIdentityResolver;
import com.silicaproxy.service.interception.ParsedPackage;
import com.silicaproxy.service.interception.ResponseIdentificationService;
import com.silicaproxy.service.interception.ResponseIdentificationService.ResponseIdentification;
import com.silicaproxy.service.interception.ResponseIdentificationService.ThrottledException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NullMarked;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.micrometer.core.annotation.Timed;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Main entry point of the proxy  : intercepts all {@code GET /**} requests
 * forwarded by the artifacts repository (or via the CONNECT tunnel from {@code LoomProxyServer}), 
 * has {@link PackageIdentificationService} identify the package/version/ecosystem, queries
 * {@link SecurityService} for the decision, 
 * then either streams the download (ALLOW) or returns a detailed 403 RFC 7807 
 * response (BLOCK) -- a 429 with {@code Retry-After} when the block only means that an upstream
 * needed for the decision is rate-limiting the proxy. Called at each dependency resolution by package managers 
 * (npm, pip, Maven) ; each call also triggers an asynchronous audit. A request its URL does not
 * identify gets a last chance from the upstream response ({@link ResponseIdentificationService}),
 * before its body is relayed.
 */
@RestController
@NullMarked
public class ProxyController {

    private static final Logger LOG = LoggerFactory.getLogger(ProxyController.class);
    private static final String HTTP_SCHEME = "http://";
    private static final String HTTPS_SCHEME = "https://";
    private static final DecisionResult UNIDENTIFIED_TARBALL_VERDICT = DecisionResult.block(DecisionSource.UNIDENTIFIED_ARTIFACT,
            "npm tarball could not be identified from its URL or from a relayed packument (unidentified-tarball-action=BLOCK).");

    private final SecurityService securityService;
    private final AuditLogService auditLogService;
    private final ProxyStreamClient proxyStreamClient;
    private final PackageIdentificationService packageIdentification;
    private final NpmPackumentIndex npmPackumentIndex;
    // Applies the configured http-only-hosts exemptions to the relayed URL.
    private final HttpsUpgradePolicy httpsUpgradePolicy;
    // Last chance for a request its URL does not identify (only when enabled).
    private final ResponseIdentificationService responseIdentification;
    private final ProxyControllerMetrics metrics;
    private final ObjectMapper objectMapper;
    // Who sent the request, recorded in the audit log.
    private final ClientIdentityResolver clientIdentityResolver;
    // Tells the client when to retry a request blocked because an upstream is rate-limiting the proxy.
    private final UpstreamThrottle upstreamThrottle;

    public ProxyController(
            SecurityService securityService,
            AuditLogService auditLogService,
            ProxyStreamClient proxyStreamClient,
            PackageIdentificationService packageIdentification,
            NpmPackumentIndex npmPackumentIndex,
            HttpsUpgradePolicy httpsUpgradePolicy,
            ResponseIdentificationService responseIdentification,
            ProxyControllerMetrics metrics,
            ObjectMapper objectMapper) {
        this(securityService, auditLogService, proxyStreamClient, packageIdentification, npmPackumentIndex,
                httpsUpgradePolicy, responseIdentification, metrics, objectMapper, ClientIdentityResolver.untrusting(),
                UpstreamThrottle.standalone());
    }

    @Autowired
    public ProxyController(
            SecurityService securityService,
            AuditLogService auditLogService,
            ProxyStreamClient proxyStreamClient,
            PackageIdentificationService packageIdentification,
            NpmPackumentIndex npmPackumentIndex,
            HttpsUpgradePolicy httpsUpgradePolicy,
            ResponseIdentificationService responseIdentification,
            ProxyControllerMetrics metrics,
            ObjectMapper objectMapper,
            ClientIdentityResolver clientIdentityResolver,
            UpstreamThrottle upstreamThrottle) {
        this.securityService = securityService;
        this.auditLogService = auditLogService;
        this.proxyStreamClient = proxyStreamClient;
        this.packageIdentification = packageIdentification;
        this.npmPackumentIndex = npmPackumentIndex;
        this.httpsUpgradePolicy = httpsUpgradePolicy;
        this.responseIdentification = responseIdentification;
        this.metrics = metrics;
        this.objectMapper = objectMapper;
        this.clientIdentityResolver = clientIdentityResolver;
        this.upstreamThrottle = upstreamThrottle;
    }

    @GetMapping("/**")
    @Timed(value = "silicaproxy.controller.requests",
            description = "Processing duration of the proxy request by the Controller",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void proxyRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        long startTime = System.currentTimeMillis();
        
        String requestUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();
        // A request out of a CONNECT tunnel reaches Tomcat in clear text : Tomcat rebuilds it as
        // http://, the scheme the client asked for is restored so that the decision, the audit, the
        // relay and the external validation services all see the https URL actually requested.
        if (requestUrl.startsWith(HTTP_SCHEME)
                && clientIdentityResolver.isTunnelled(request.getRemoteAddr(), request.getRemotePort())) {
            requestUrl = HTTPS_SCHEME + requestUrl.substring(HTTP_SCHEME.length());
        }
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

        // Extracted once : the npm metadata detector reads the client hints (Accept / User-Agent /
        // npm-*) and the forwarder replays the same headers upstream.
        HttpHeaders headers = extractHeaders(request);
        ClientIdentity client = clientIdentityResolver.resolve(request.getRemoteAddr(), request.getRemotePort(), headers);
        String forwardUrl = httpsUpgradePolicy.upgrade(fullUrl, request.getLocalPort());
        Identification identification = packageIdentification.identify(fullUrl, forwardUrl, headers);
        ParsedPackage parsed = identification.pkg();
        String packageName = parsed.packageName();
        String version = parsed.version();
        String ecosystem = parsed.ecosystem();

        if (identification.outcome() == Outcome.BYPASS) {
            if (responseIdentification.isEnabled()) {
                forwardIdentifyingResponse(fullUrl, forwardUrl, headers, client, response, identification, startTime);
            } else {
                recordBypass(parsed, forwardUrl);
                forwardRequest(forwardUrl, headers, response, identification.learnPackument());
            }
            return;
        }

        DecisionResult decision = identification.outcome() == Outcome.BLOCK_UNIDENTIFIED_TARBALL
                ? UNIDENTIFIED_TARBALL_VERDICT
                : securityService.getDecision(packageName, version, ecosystem, fullUrl);
        if (applyDecision(decision, parsed, fullUrl, client, startTime, response)) {
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Request ALLOWED : Forwarding to {}", forwardUrl);
        }
        forwardRequest(forwardUrl, headers, response, false);
    }

    private void recordBypass(ParsedPackage parsed, String forwardUrl) {
        metrics.recordBypass(parsed.ecosystem());
        if (parsed.hasEcosystem()) {
            // Metadata/index traffic (packuments, dist-tags, search…) is expected on every
            // install and carries nothing to vet : not a warning.
            LOG.info("Non-package resource (metadata/index) for ecosystem {}. Bypassing security control for : {}",
                    parsed.ecosystem(), forwardUrl);
        } else {
            LOG.warn("Unknown ecosystem. Bypassing security control for : {}", forwardUrl);
        }
    }

    /**
     * Records, audits and, when blocked, answers the 403 (or the 429 of an {@code UPSTREAM_THROTTLED}
     * block) for a decision on {@code pkg}.
     *
     * @return whether the request was blocked (the response is then already written)
     */
    private boolean applyDecision(DecisionResult decision, ParsedPackage pkg, String fullUrl, ClientIdentity client,
            long startTime, HttpServletResponse response) throws IOException {
        String packageName = pkg.packageName();
        String version = pkg.version();
        String ecosystem = pkg.ecosystem();
        long executionTimeMs = System.currentTimeMillis() - startTime;
        metrics.recordDecision(decision, ecosystem, executionTimeMs);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Final decision for {}/{} (ecosystem={}) : RESULT={} (Source={}, Reason: {}) [Calculated in {}ms]",
                    packageName, version, ecosystem, decision.result(), decision.sourceType(), decision.reason(), executionTimeMs);
        }

        auditLogService.logAudit(
                packageName,
                version,
                ecosystem,
                decision.sourceType().name(),
                decision.result().name(),
                decision.reason(),
                (int) executionTimeMs,
                fullUrl,
                client
        );

        if (decision.isBlocked()) {
            LOG.warn("Request BLOCKED for {}/{} (ecosystem={}, step={}) : {}",
                    packageName, version, ecosystem, decision.sourceType(), decision.reason());
            sendProblemDetail(response, packageName, version, ecosystem, decision);
            return true;
        }
        return false;
    }

    /**
     * Relays an unidentified request, unless the upstream response identifies the package : its
     * announced file digest is looked up before the body is relayed, and a package found that way
     * goes through the security decision like one identified from its URL. A blocked body is never
     * relayed ; an allowed one is relayed while its digest is recomputed, and the connection is
     * cut if it does not match the announced one.
     */
    private void forwardIdentifyingResponse(String fullUrl, String forwardUrl, HttpHeaders headers, ClientIdentity client,
            HttpServletResponse response, Identification identification, long startTime) throws IOException {
        String ecosystem = identification.pkg().ecosystem();
        try (ProxyStreamClient.StreamResponse streamResponse = proxyStreamClient.streamContent(forwardUrl, headers)) {
            Optional<ResponseIdentification> found = responseIdentification.identify(streamResponse.status(), streamResponse.headers());
            if (found.isEmpty()) {
                recordBypass(identification.pkg(), forwardUrl);
                relay(streamResponse, forwardUrl, response, identification.learnPackument());
                return;
            }
            ParsedPackage pkg = found.get().pkg();
            ecosystem = pkg.ecosystem();
            DecisionResult decision = securityService.getDecision(pkg.packageName(), pkg.version(), ecosystem, fullUrl);
            if (applyDecision(decision, pkg, fullUrl, client, startTime, response)) {
                // The upstream body is dropped unread : try-with-resources releases the connection.
                return;
            }
            copyStatusAndHeaders(streamResponse, response);
            ChecksumVerifyingRelay.relay(streamResponse.body(), response.getOutputStream(), found.get().digest());
        } catch (ThrottledException e) {
            // deps.dev could not identify the file because it is rate-limiting the proxy (on-throttle
            // FAIL_CLOSED) : blocked like any decision, the upstream body is dropped unread.
            applyDecision(DecisionResult.block(DecisionSource.UPSTREAM_THROTTLED, e.getMessage()),
                    identification.pkg(), fullUrl, client, startTime, response);
        } catch (ChecksumMismatchException e) {
            LOG.error("Upstream body digest does not match the announced one, download aborted for {} : {}",
                    forwardUrl, e.getMessage());
            metrics.recordChecksumMismatch(ecosystem);
            if (!response.isCommitted()) {
                // Nothing reached the client yet (small body) : a clean error instead of a cut.
                response.reset();
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Upstream body does not match its checksum.");
                return;
            }
            // Part of the body is already on the wire : rethrown so the servlet container aborts
            // the connection and the client never takes the truncated body for a complete one.
            throw e;
        } catch (Exception e) {
            handleForwardFailure(e, forwardUrl, response);
        }
    }

    private void forwardRequest(String fullUrl, HttpHeaders headers, HttpServletResponse response,
            boolean learnPackument) throws IOException {
        // try-with-resources: streamContent() opens the upstream connection, and nothing else
        // ever released it (StreamUtils.copy() only reads the body stream, it never closes the
        // response) -- every proxied request used to leak a connection, including on partial
        // copies or bodyless responses.
        try (ProxyStreamClient.StreamResponse streamResponse = proxyStreamClient.streamContent(fullUrl, headers)) {
            relay(streamResponse, fullUrl, response, learnPackument);
        } catch (Exception e) {
            handleForwardFailure(e, fullUrl, response);
        }
    }

    /**
     * A client that hangs up mid-relay is not an upstream failure : it is logged briefly and nothing
     * is written back. Any other failure after the response was committed cannot become a clean
     * error page, so it is rethrown for the servlet container to abort the connection.
     */
    private void handleForwardFailure(Exception e, String url, HttpServletResponse response) throws IOException {
        if (isClientAbort(e)) {
            LOG.debug("Client closed the connection while relaying {} : {}", url, e.getMessage());
            return;
        }
        LOG.error("Proxy error to upstream registry when forwarding request {}", url, e);
        if (response.isCommitted()) {
            throw e instanceof IOException io ? io : new IOException(e);
        }
        response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Proxy error to upstream registry.");
    }

    static boolean isClientAbort(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (t instanceof org.apache.catalina.connector.ClientAbortException
                    || t instanceof org.springframework.web.context.request.async.AsyncRequestNotUsableException) {
                return true;
            }
        }
        return false;
    }

    private void relay(ProxyStreamClient.StreamResponse streamResponse, String fullUrl, HttpServletResponse response,
            boolean learnPackument) throws IOException {
        copyStatusAndHeaders(streamResponse, response);
        if (streamResponse.body() != null) {
            if (learnPackument && isJsonOk(streamResponse)) {
                npmPackumentIndex.relayAndIndex(streamResponse.body(),
                        streamResponse.headers().getFirst(HttpHeaders.CONTENT_ENCODING),
                        contentLength(streamResponse.headers()), fullUrl, response.getOutputStream());
            } else {
                // Buffer of 16 KB (default in StreamUtils.copy)
                StreamUtils.copy(streamResponse.body(), response.getOutputStream());
            }
        }
    }

    private static void copyStatusAndHeaders(ProxyStreamClient.StreamResponse streamResponse,
            HttpServletResponse response) {
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
    }

    // -1 when absent or malformed : HttpHeaders.getContentLength() throws on an unparseable
    // value, and this one comes from the upstream registry.
    private static long contentLength(HttpHeaders headers) {
        try {
            return headers.getContentLength();
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static boolean isJsonOk(ProxyStreamClient.StreamResponse streamResponse) {
        if (streamResponse.status() != HttpStatus.OK) {
            return false;
        }
        String contentType = streamResponse.headers().getFirst(HttpHeaders.CONTENT_TYPE);
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json");
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
        // A block that only means "an upstream is rate-limiting the proxy" : 429 rather than 403, so
        // the artifacts repository retries later instead of remembering the artifact as forbidden
        // or missing ; never stored by any cache on the way.
        boolean throttled = decision.sourceType() == DecisionSource.UPSTREAM_THROTTLED;
        HttpStatus status = throttled ? HttpStatus.TOO_MANY_REQUESTS : HttpStatus.FORBIDDEN;
        response.setStatus(status.value());
        if (throttled) {
            response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(upstreamThrottle.retryAfterSeconds()));
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        }
        response.setContentType("application/problem+json");
        response.setCharacterEncoding("UTF-8");

        // RFC 7807 body, written directly to the response output stream to bypass the stream
        // forwarder, so it is serialized here rather than returned as a ResponseEntity<ProblemDetail>.
        // Built as a plain map and serialized through Jackson (rather than hand-formatted via
        // String.format) so a block reason or package name containing quotes, backslashes, or
        // control characters always produces valid JSON instead of a corrupted response body.
        // Written to the raw OutputStream rather than through PrintWriter.print/write(String):
        // those two are exactly the API shape FindSecBugs' XSS_SERVLET check flags on any
        // servlet response, regardless of declared Content-Type.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", status.getReasonPhrase());
        body.put("status", status.value());
        body.put("detail", decision.reason());
        body.put("instance", "");
        body.put("step", decision.sourceType().name());
        body.put("package", packageName);
        body.put("version", version);
        body.put("ecosystem", ecosystem);
        body.put("error", switch (decision.sourceType()) {
            case REGISTRY_QUARANTINE -> "QuarantineBlocked";
            case UPSTREAM_THROTTLED -> "UpstreamThrottled";
            default -> "SecurityBlocked";
        });

        objectMapper.writeValue(response.getOutputStream(), body);
        response.getOutputStream().flush();
    }
}
