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

import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.List;

/**
 * {@link ProxySelector} honoring the {@code non-proxy-hosts} list : corresponding hosts 
 * always bypass the configured corporate proxy.
 */
@NullMarked
public class NonProxyAwareProxySelector extends ProxySelector {

    private final Proxy corporateProxy;
    private final NonProxyHostMatcher nonProxyHostMatcher;

    public NonProxyAwareProxySelector(Proxy corporateProxy, String nonProxyHosts) {
        this.corporateProxy = corporateProxy;
        this.nonProxyHostMatcher = new NonProxyHostMatcher(nonProxyHosts);
    }

    @Override
    public List<Proxy> select(URI uri) {
        String host = uri.getHost();
        if (host != null && nonProxyHostMatcher.matches(host)) {
            return List.of(Proxy.NO_PROXY);
        }
        return List.of(corporateProxy);
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        // No specific retry/fallback : the caller already handles network errors.
    }
}
