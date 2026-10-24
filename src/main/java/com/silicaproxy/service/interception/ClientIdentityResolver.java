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

import com.silicaproxy.model.dto.ClientIdentity;
import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Resolves who sent an intercepted request, for the audit log ({@link ClientIdentity}).
 *
 * <p><b>Client address.</b> Every request reaches Tomcat through {@link LoomProxyServer}, from
 * 127.0.0.1 : the real socket peer is looked up in the {@link ProxyConnectionRegistry}, by the
 * source port of that loopback connection (a client reaching the Tomcat port directly is taken
 * as is). X-Forwarded-For is spoofable by any client, so it is only honoured when that peer is
 * one of {@code silicaproxy.proxy.trusted-proxies} : the hops are then walked from the right,
 * skipping trusted ones, and the right-most untrusted hop is the client (each trusted proxy
 * appends the address it received the request from, so only the hops on the right are vouched
 * for). Empty (default) = X-Forwarded-For is ignored.
 *
 * <p><b>What a repository manager relays.</b> Artifactory and Nexus 3 fetch from their remote /
 * proxy repositories with their own HTTP client, on a cache miss only : neither relays the end
 * client's address, X-Forwarded-For or User-Agent (they send their own, {@code Artifactory/7.x},
 * {@code Nexus/3.x}), so behind them the audit log records the repository manager itself. Both can
 * tag their outbound requests : Artifactory remote repositories accept static custom HTTP headers
 * (e.g. {@code X-Silica-Client: artifactory-npm-remote}), Nexus 3 a global User-Agent suffix
 * (System > HTTP). Per-workstation identity is only available for clients using SilicaProxy
 * directly (HTTP proxy / CONNECT), or through an HTTP reverse proxy listed in trusted-proxies.
 *
 * <p><b>Client id.</b> The optional {@code X-Silica-Client} header, else the username of a
 * {@code Basic} Proxy-Authorization (the one of the CONNECT for an HTTPS tunnel, read by
 * LoomProxyServer) ; the password is never kept.
 */
@Component
@NullMarked
public class ClientIdentityResolver {

    /** Optional, client-declared identity (CI runner name, project…). */
    static final String CLIENT_HEADER = "X-Silica-Client";

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    // Only the dotted-quad form : InetAddress.ofLiteral also takes the legacy "1.2.3" / "16909060".
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern PORT = Pattern.compile(":\\d{1,5}");

    private final List<Network> trustedProxies;
    private final ProxyConnectionRegistry connectionRegistry;

    @Autowired
    public ClientIdentityResolver(SilicaProxyProperties properties, ProxyConnectionRegistry connectionRegistry) {
        this(parseNetworks(properties.proxy().trustedProxies()), connectionRegistry);
    }

    private ClientIdentityResolver(List<Network> trustedProxies, ProxyConnectionRegistry connectionRegistry) {
        this.trustedProxies = trustedProxies;
        this.connectionRegistry = connectionRegistry;
    }

    /** Resolver trusting no proxy, with no relayed connection, used when no configuration is injected. */
    public static ClientIdentityResolver untrusting() {
        return new ClientIdentityResolver(List.of(), new ProxyConnectionRegistry());
    }

    /** Resolver trusting the comma-separated IPs / CIDR ranges of {@code csvTrustedProxies}. */
    public static ClientIdentityResolver fromCsv(String csvTrustedProxies, ProxyConnectionRegistry connectionRegistry) {
        return new ClientIdentityResolver(parseNetworks(csvTrustedProxies), connectionRegistry);
    }

    /**
     * @param remoteAddr the address of the connection Tomcat accepted ({@code getRemoteAddr()})
     * @param remotePort the source port of that connection ({@code getRemotePort()})
     * @param headers the request headers
     */
    public ClientIdentity resolve(String remoteAddr, int remotePort, HttpHeaders headers) {
        String peer = remoteAddr;
        String connectUser = null;
        boolean tunnelled = false;
        ProxyConnectionRegistry.Peer relayed = isLoopback(remoteAddr) ? connectionRegistry.lookup(remotePort) : null;
        if (relayed != null) {
            peer = relayed.address();
            connectUser = relayed.connectUser();
            tunnelled = relayed.tunnelled();
        }
        String clientId = firstNonBlank(headers.getFirst(CLIENT_HEADER), connectUser,
                ClientHeaders.basicAuthUser(headers.getFirst(HttpHeaders.PROXY_AUTHORIZATION)));
        // Inside a CONNECT tunnel, no proxy in between could have written X-Forwarded-For : only
        // the end client did, so it is never trusted there.
        return new ClientIdentity(clientIp(peer, tunnelled ? null : headers.get(X_FORWARDED_FOR)),
                headers.getFirst(HttpHeaders.USER_AGENT), clientId);
    }

    private String clientIp(String peer, @Nullable List<String> forwardedFor) {
        if (forwardedFor == null || !isTrusted(parseIp(peer))) {
            return peer;
        }
        List<String> hops = new ArrayList<>();
        for (String value : forwardedFor) {
            Arrays.stream(value.split(",")).map(String::strip).filter(hop -> !hop.isEmpty()).forEach(hops::add);
        }
        String client = peer;
        for (int i = hops.size() - 1; i >= 0; i--) {
            InetAddress hop = parseHop(hops.get(i));
            if (hop == null) {
                // Garbage written by an untrusted party : the last vouched-for hop is kept.
                break;
            }
            client = hop.getHostAddress();
            if (!isTrusted(hop)) {
                break;
            }
        }
        return client;
    }

    private boolean isTrusted(@Nullable InetAddress address) {
        return address != null && trustedProxies.stream().anyMatch(network -> network.contains(address));
    }

    private static boolean isLoopback(String address) {
        InetAddress parsed = parseIp(address);
        return parsed != null && parsed.isLoopbackAddress();
    }

    private static @Nullable String firstNonBlank(@Nullable String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    /** An X-Forwarded-For hop : an IP literal, possibly bracketed (IPv6) and followed by a port, or null. */
    static @Nullable InetAddress parseHop(String value) {
        String ip = value.strip();
        if (ip.startsWith("[")) {
            int close = ip.indexOf(']');
            if (close < 0 || !isPortOrEmpty(ip.substring(close + 1))) {
                return null;
            }
            ip = ip.substring(1, close);
        } else if (ip.indexOf(':') > 0 && ip.indexOf(':') == ip.lastIndexOf(':')) {
            // IPv4 with a port
            if (!isPortOrEmpty(ip.substring(ip.indexOf(':')))) {
                return null;
            }
            ip = ip.substring(0, ip.indexOf(':'));
        }
        return parseIp(ip);
    }

    private static boolean isPortOrEmpty(String suffix) {
        return suffix.isEmpty() || PORT.matcher(suffix).matches();
    }

    /** A bare IPv4 / IPv6 literal (a zone id is dropped), or null ; never resolves a hostname. */
    static @Nullable InetAddress parseIp(String value) {
        String ip = value.strip();
        int zone = ip.indexOf('%');
        if (zone >= 0) {
            ip = ip.substring(0, zone);
        }
        if (ip.indexOf(':') < 0 && !IPV4.matcher(ip).matches()) {
            return null;
        }
        try {
            return InetAddress.ofLiteral(ip);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static List<Network> parseNetworks(String csv) {
        return Arrays.stream(csv.split(","))
                .map(String::strip)
                .filter(entry -> !entry.isEmpty())
                .map(Network::parse)
                .toList();
    }

    /** An IP or CIDR range of {@code silicaproxy.proxy.trusted-proxies}. */
    private static final class Network {

        private final byte[] address;
        private final int prefixLength;

        private Network(byte[] address, int prefixLength) {
            this.address = address;
            this.prefixLength = prefixLength;
        }

        static Network parse(String entry) {
            int slash = entry.indexOf('/');
            InetAddress address = parseIp(slash >= 0 ? entry.substring(0, slash) : entry);
            if (address == null) {
                throw new IllegalArgumentException("Invalid silicaproxy.proxy.trusted-proxies entry (IP or CIDR expected): " + entry);
            }
            int maxPrefix = address.getAddress().length * 8;
            int prefix;
            try {
                prefix = slash >= 0 ? Integer.parseInt(entry.substring(slash + 1).strip()) : maxPrefix;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid prefix length in silicaproxy.proxy.trusted-proxies entry: " + entry, e);
            }
            if (prefix < 0 || prefix > maxPrefix) {
                throw new IllegalArgumentException("Invalid prefix length in silicaproxy.proxy.trusted-proxies entry: " + entry);
            }
            return new Network(address.getAddress(), prefix);
        }

        boolean contains(InetAddress candidate) {
            byte[] bytes = candidate.getAddress();
            if (bytes.length != address.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (bytes[i] != address[i]) {
                    return false;
                }
            }
            int remainingBits = prefixLength % 8;
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits) & 0xFF;
            return (bytes[fullBytes] & mask) == (address[fullBytes] & mask);
        }
    }
}
