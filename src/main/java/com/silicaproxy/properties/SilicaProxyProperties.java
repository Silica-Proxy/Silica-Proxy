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


package com.silicaproxy.properties;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "silicaproxy")
@Validated
@NullMarked
public record SilicaProxyProperties(
    @NotNull QuarantineProperties quarantine,
    @NotNull DeprecationProperties deprecation,
    @NotNull SeverityThresholdProperties severityThreshold,
    @NotNull Map<String, ApiFallbackProperties> apiFallback,
    @NotNull GitOpsProperties gitops,
    @NotNull CorporateProxyProperties corporateProxy,
    @NotNull RegistriesProperties registries,
    @NotNull ProxyProperties proxy,
    @NotNull SecurityProperties security,
    @NotNull HttpClientProperties httpClient,
    @NotNull SslMitmProperties sslMitm,
    @NotNull ApiCacheProperties apiCache,
    @NotNull OsvIncrementalProperties osvIncremental,
    @NotNull ApiCallLogProperties apiCallLog,
    @NotNull ExternalValidationProperties externalValidation
) {
    public SilicaProxyProperties {
        apiFallback = Collections.unmodifiableMap(new HashMap<>(apiFallback));
    }

    public record ProxyProperties(
        int port
    ) {}

    // Timeouts for outgoing HTTP clients (registries, security APIs, external validation).
    // Without timeout, a silent remote server (not in error, just frozen) would block
    // indefinitely the virtual thread caller, preventing fail-open/fail-closed from triggering.
    public record HttpClientProperties(
        int connectTimeoutSeconds,
        int registriesReadTimeoutSeconds,
        int securityApisReadTimeoutSeconds,
        int externalValidationReadTimeoutSeconds
    ) {}

    public record SecurityProperties(
        @NotNull SsrfProtectionProperties ssrfProtection
    ) {}

    public record SsrfProtectionProperties(
        boolean enabled
    ) {}

    public record RegistriesProperties(
        @NotBlank String npmUrl,
        @NotBlank String pypiUrl,
        @NotBlank String mavenUrl
    ) {}

    public record QuarantineProperties(
        boolean enabled,
        int defaultMinAgeDays,
        boolean failOpen,
        @NotNull Map<String, EcosystemQuarantineProperties> ecosystems
    ) {
        public QuarantineProperties {
            ecosystems = Collections.unmodifiableMap(new HashMap<>(ecosystems));
        }
    }

    public record EcosystemQuarantineProperties(
        boolean enabled,
        int minAgeDays
    ) {}

    public record DeprecationProperties(
        boolean enabled,
        @NotNull Map<String, Boolean> ecosystems
    ) {
        public DeprecationProperties {
            ecosystems = Collections.unmodifiableMap(new HashMap<>(ecosystems));
        }
    }

    public record SeverityThresholdProperties(
        boolean enabled,
        @NotBlank String defaultMaxAllowedSeverity,
        double defaultMaxAllowedCvss,
        @NotNull Map<String, EcosystemSeverityProperties> ecosystems
    ) {
        public SeverityThresholdProperties {
            ecosystems = Collections.unmodifiableMap(new HashMap<>(ecosystems));
        }
    }

    public record EcosystemSeverityProperties(
        @NotBlank String maxAllowedSeverity,
        double maxAllowedCvss
    ) {}

    public record ApiFallbackProperties(
        boolean enabled,
        @Nullable String apiKey,
        @NotBlank String url
    ) {}

    public record GitOpsProperties(
        boolean enabled,
        @NotBlank String repositoryUrl,
        @NotBlank String directoryPath,
        @Nullable String cloneToken,
        int syncIntervalMinutes
    ) {}

    public record CorporateProxyProperties(
        boolean enabled,
        @NotBlank String host,
        int port,
        @NotBlank String nonProxyHosts,
        @NotNull CorporateProxyScopeProperties scope
    ) {}

    // Enable or disable relay through corporate proxy independently by outgoing traffic category,
    // once `corporate-proxy.enabled` is true. The internal Git repository (GitOps) is
    // distinguished from external Git repositories (GHSA/OpenSSF/GitLab) because it is typically
    // intra-network traffic that dont necessarily need to go through the outgoing proxy to Internet.
    public record CorporateProxyScopeProperties(
        boolean registries,
        boolean securityApis,
        boolean externalGitRepositories,
        boolean internalGitRepository,
        boolean externalValidation
    ) {}

    // Persistence of MITM CA between restarts. If caKeystorePath is not empty, the CA is 
    // loaded from existing PKCS12 keystore (or created and saved at first startup). 
    // Without this configuration, a new CA is generated at each startup. 
    // caCertExportPath : path where to export the public PEM certificate (ex. shared Docker volume). 
    // If empty, the cert is written in the same folder as the keystore, or in the current directory.
    public record SslMitmProperties(
        @Nullable String caKeystorePath,
        @Nullable String caKeystorePassword,
        @Nullable String caCertExportPath
    ) {}

    public record OsvIncrementalProperties(
        boolean enabled,
        @NotBlank String gcsBaseUrl,
        int initialLookbackHours
    ) {}

    // Audit of calls to external security APIs in api_call_log.
    // Disabled by default : can generate one line per unknown proxy request, high volume.
    public record ApiCallLogProperties(
        boolean enabled,
        int flushIntervalSeconds,
        int bufferCapacity
    ) {}

    // Cache of results from external APIs (OSV Live, deps.dev).
    // Allows to configure differently TTL for ALLOW and BLOCK verdicts,
    // and optionally not cache ALLOW at all.
    public record ApiCacheProperties(
        boolean cacheAllowVerdict,
        int blockVerdictTtlMinutes,
        int allowVerdictTtlMinutes
    ) {}

    public record ExternalValidationProperties(
        @Nullable String callbackBaseUrl,
        boolean triggerAsyncOnSyncBlock,
        @Nullable Map<String, ExternalValidationServiceProperties> services
    ) {
        public ExternalValidationProperties {
            if (services == null) {
                services = Map.of();
            } else {
                services = Collections.unmodifiableMap(new HashMap<>(services));
            }
        }
    }

    public record ExternalValidationServiceProperties(
        boolean enabled,
        @NotBlank String url,
        @Nullable String apiKey,
        @NotBlank String mode,
        int timeoutSeconds,
        boolean failOpen,
        boolean blocking,
        int cacheTtlMinutes,
        int pendingTtlMinutes
    ) {}
}
