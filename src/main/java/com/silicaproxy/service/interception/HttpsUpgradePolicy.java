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


package com.silicaproxy.service.interception;

import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Upgrades the {@code http://} URLs relayed by the proxy to {@code https://}, so that both the
 * upstream relay and the registry metadata lookups reach registries that refuse plain HTTP
 * (e.g. plugins.gradle.org answers 403 behind Cloudflare). Loopback/container hosts and the hosts
 * listed in {@code silicaproxy.proxy.http-only-hosts} are left untouched.
 */
@Component
@NullMarked
public class HttpsUpgradePolicy {

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "host.docker.internal");

    private final Set<String> httpOnlyHosts;

    @Autowired
    public HttpsUpgradePolicy(SilicaProxyProperties properties) {
        this(parseHosts(properties.proxy().httpOnlyHosts()));
    }

    private HttpsUpgradePolicy(Set<String> httpOnlyHosts) {
        this.httpOnlyHosts = httpOnlyHosts;
    }

    /** Policy upgrading every non-local host, used when no configuration is injected. */
    public static HttpsUpgradePolicy upgradeAll() {
        return new HttpsUpgradePolicy(Set.of());
    }

    /** Policy leaving the comma-separated, case-insensitive {@code csvHosts} on plain HTTP. */
    public static HttpsUpgradePolicy fromCsv(String csvHosts) {
        return new HttpsUpgradePolicy(parseHosts(csvHosts));
    }

    private static Set<String> parseHosts(String csvHosts) {
        return Arrays.stream(csvHosts.split(","))
                .map(host -> host.trim().toLowerCase(Locale.ROOT))
                .filter(host -> !host.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    // Ports the servlet container itself is listening on can leak into request.getRequestURL()'s
    // reconstructed authority even when the original absolute-URI request line had no port (or a
    // different one). Comparing against localPort (the actual local socket port this connection
    // was accepted on, immune to Host-header or request-line spoofing) distinguishes that
    // connector artifact from a genuine port that was part of the original request (e.g. a
    // private mirror on a non-standard port), which must be preserved rather than silently dropped.
    public String upgrade(String urlString, int localPort) {
        if (urlString.startsWith("http://")) {
            try {
                URI uri = URI.create(urlString);
                String host = uri.getHost();
                if (host != null && !LOCAL_HOSTS.contains(host)
                        && !httpOnlyHosts.contains(host.toLowerCase(Locale.ROOT))) {
                    int port = uri.getPort();
                    boolean isConnectorPort = port == localPort;
                    String path = uri.getRawPath();
                    String query = uri.getRawQuery();
                    String newUrl = "https://" + host
                            + (port != -1 && !isConnectorPort ? ":" + port : "")
                            + (path != null ? path : "");
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
