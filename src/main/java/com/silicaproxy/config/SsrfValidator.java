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


package com.silicaproxy.config;

import com.silicaproxy.properties.SilicaProxyProperties;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

@Component
@NullMarked
public class SsrfValidator {

    private boolean enabled;

    public SsrfValidator(SilicaProxyProperties properties) {
        this.enabled = properties.security().ssrfProtection().enabled();
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void validateUrl(String urlString) {
        if (!enabled) {
            return;
        }
        URI uri = URI.create(urlString);
        String host = uri.getHost();

        if (host == null) {
            // Fail closed : a URL string that URI can't parse into a host should not get the
            // benefit of the doubt, same reasoning as the UnknownHostException case below.
            throw new SecurityException("SSRF Blocked: URL has no resolvable host: " + urlString);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (address.isLoopbackAddress()
                        || address.isLinkLocalAddress()
                        || address.isAnyLocalAddress()
                        || address.isSiteLocalAddress()
                        || isUniqueLocalIpv6(address)
                        || isCarrierGradeNat(address)) {
                    throw new SecurityException("SSRF Blocked: The IP address " + address.getHostAddress() + " is restricted.");
                }
            }
        } catch (UnknownHostException e) {
            // Fail closed rather than silently letting an unresolvable host through: this is a
            // security control, and a host that can't be resolved right now (registered by an
            // attacker to appear only during a later, separate lookup, or genuinely misconfigured)
            // should not get the benefit of the doubt.
            throw new SecurityException("SSRF Blocked: Unable to resolve host " + host + ".", e);
        }
    }

    // fc00::/7 (RFC 4193 Unique Local Address) : InetAddress.isSiteLocalAddress() only covers
    // the deprecated fec0::/10 range for IPv6, not the modern ULA range actually used today.
    private boolean isUniqueLocalIpv6(InetAddress address) {
        if (!(address instanceof Inet6Address)) {
            return false;
        }
        return (address.getAddress()[0] & 0xFE) == 0xFC;
    }

    // 100.64.0.0/10 (RFC 6598 Carrier-Grade NAT / Shared Address Space) : not covered by any
    // InetAddress built-in predicate, but routable to internal infrastructure behind a CGN.
    private boolean isCarrierGradeNat(InetAddress address) {
        if (!(address instanceof Inet4Address)) {
            return false;
        }
        byte[] bytes = address.getAddress();
        return (bytes[0] & 0xFF) == 100 && (bytes[1] & 0xC0) == 0x40;
    }
}
