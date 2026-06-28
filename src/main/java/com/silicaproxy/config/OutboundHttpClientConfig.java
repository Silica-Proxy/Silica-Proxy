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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.http.HttpClient;
import java.time.Duration;

@Configuration
@NullMarked
public class OutboundHttpClientConfig {

    private final SilicaProxyProperties properties;

    public OutboundHttpClientConfig(SilicaProxyProperties properties) {
        this.properties = properties;
    }

    @Bean
    public ClientHttpRequestFactory registriesRequestFactory() {
        Duration readTimeout = Duration.ofSeconds(properties.httpClient().registriesReadTimeoutSeconds());
        return buildRequestFactory(properties.corporateProxy().scope().registries(), readTimeout);
    }

    @Bean
    public ClientHttpRequestFactory securityApisRequestFactory() {
        Duration readTimeout = Duration.ofSeconds(properties.httpClient().securityApisReadTimeoutSeconds());
        return buildRequestFactory(properties.corporateProxy().scope().securityApis(), readTimeout);
    }

    private ClientHttpRequestFactory buildRequestFactory(boolean scopeEnabled, Duration readTimeout) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(properties.httpClient().connectTimeoutSeconds()));
        if (properties.corporateProxy().enabled() && scopeEnabled) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(properties.corporateProxy().host(), properties.corporateProxy().port()));
            builder.proxy(new NonProxyAwareProxySelector(proxy, properties.corporateProxy().nonProxyHosts()));
        }
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(builder.build());
        factory.setReadTimeout(readTimeout);
        return factory;
    }
}
