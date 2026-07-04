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
            return;
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (address.isLoopbackAddress()
                        || address.isLinkLocalAddress()
                        || address.isAnyLocalAddress()
                        || address.isSiteLocalAddress()) {
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
}
