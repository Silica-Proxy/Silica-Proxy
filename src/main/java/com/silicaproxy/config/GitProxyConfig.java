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
import jakarta.annotation.PreDestroy;
import org.eclipse.jgit.transport.HttpTransport;
import org.eclipse.jgit.transport.http.HttpConnection;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;
import org.eclipse.jgit.transport.http.JDKHttpConnectionFactory;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;

@Component
@NullMarked
public class GitProxyConfig {

    private static final Logger LOG = LoggerFactory.getLogger(GitProxyConfig.class);

    private @Nullable HttpConnectionFactory previousFactory;

    public GitProxyConfig(SilicaProxyProperties properties) {
        SilicaProxyProperties.CorporateProxyProperties corporateProxy = properties.corporateProxy();
        if (!corporateProxy.enabled()) {
            return;
        }

        Proxy proxy = new Proxy(Proxy.Type.HTTP,
                new InetSocketAddress(corporateProxy.host(), corporateProxy.port()));
        NonProxyHostMatcher nonProxyHostMatcher = new NonProxyHostMatcher(corporateProxy.nonProxyHosts());
        String internalGitHost = extractHost(properties.gitops().repositoryUrl());

        previousFactory = HttpTransport.getConnectionFactory();
        HttpTransport.setConnectionFactory(new ScopedHttpConnectionFactory(
                proxy, nonProxyHostMatcher, internalGitHost,
                corporateProxy.scope().externalGitRepositories(),
                corporateProxy.scope().internalGitRepository()));

        LOG.info("Corporate proxy configured for JGit (host={}, port={}) - internal GitOps repository "
                        + "({}) : relay {} ; external Git repositories : relay {}",
                corporateProxy.host(), corporateProxy.port(), internalGitHost,
                corporateProxy.scope().internalGitRepository() ? "enabled" : "disabled",
                corporateProxy.scope().externalGitRepositories() ? "enabled" : "disabled");
    }

    @PreDestroy
    void restoreConnectionFactory() {
        if (previousFactory != null) {
            HttpTransport.setConnectionFactory(previousFactory);
        }
    }

    private static @Nullable String extractHost(String repositoryUrl) {
        try {
            return URI.create(repositoryUrl).getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private static final class ScopedHttpConnectionFactory implements HttpConnectionFactory {

        private final HttpConnectionFactory delegate = new JDKHttpConnectionFactory();
        private final Proxy corporateProxy;
        private final NonProxyHostMatcher nonProxyHostMatcher;
        private final @Nullable String internalGitHost;
        private final boolean externalGitEnabled;
        private final boolean internalGitEnabled;

        private ScopedHttpConnectionFactory(
                Proxy corporateProxy,
                NonProxyHostMatcher nonProxyHostMatcher,
                @Nullable String internalGitHost,
                boolean externalGitEnabled,
                boolean internalGitEnabled) {
            this.corporateProxy = corporateProxy;
            this.nonProxyHostMatcher = nonProxyHostMatcher;
            this.internalGitHost = internalGitHost;
            this.externalGitEnabled = externalGitEnabled;
            this.internalGitEnabled = internalGitEnabled;
        }

        @Override
        public HttpConnection create(URL url) throws IOException {
            return delegate.create(url, resolveProxy(url));
        }

        @Override
        public HttpConnection create(URL url, Proxy ignoredProxy) throws IOException {
            return delegate.create(url, resolveProxy(url));
        }

        private Proxy resolveProxy(URL url) {
            String host = url.getHost();
            boolean isInternal = internalGitHost != null && internalGitHost.equalsIgnoreCase(host);
            boolean scopeEnabled = isInternal ? internalGitEnabled : externalGitEnabled;
            if (!scopeEnabled || nonProxyHostMatcher.matches(host)) {
                return Proxy.NO_PROXY;
            }
            return corporateProxy;
        }
    }
}
