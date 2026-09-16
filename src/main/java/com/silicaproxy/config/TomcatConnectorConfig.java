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

import org.apache.catalina.connector.Connector;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Tomcat rejects (400) any request target containing an encoded slash ({@code %2F}) by default
 * -- a legacy path-traversal guard. This proxy relays package-manager traffic verbatim
 * ({@code LoomProxyServer.forwardToTomcat}) and never routes on path segments itself
 * ({@code ProxyController} maps everything through a single {@code /**} catch-all), so that
 * guard only breaks legitimate upstream requests here (e.g. npm's scoped-package packument URLs,
 * such as JSR's npm-compatible registry encoding {@code @scope/name} as {@code @scope%2Fname}).
 * "passthrough" keeps the segment encoded exactly as received instead of decoding it, so the
 * byte-for-byte forward to the real registry stays faithful to what the client sent.
 */
@Configuration
@NullMarked
public class TomcatConnectorConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> encodedSlashPassthroughCustomizer() {
        return factory -> factory.addConnectorCustomizers(
                (Connector connector) -> connector.setEncodedSolidusHandling("passthrough"));
    }
}
