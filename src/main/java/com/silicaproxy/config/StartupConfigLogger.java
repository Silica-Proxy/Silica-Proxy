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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Logs, once the application is fully started, every {@link SilicaProxyProperties} value
 * actually bound from configuration (application.yaml plus environment overrides) as an
 * ASCII tree built by {@link ConfigTreePrinter}. The tree follows the declaration order of
 * {@link SilicaProxyProperties}, so operators can see both the effective values and the
 * order in which configuration sections are organized in a single log line at startup.
 */
@Component
@NullMarked
public class StartupConfigLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(StartupConfigLogger.class);

    private final SilicaProxyProperties properties;

    public StartupConfigLogger(SilicaProxyProperties properties) {
        this.properties = properties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logConfigurationTree() {
        LOGGER.info("Effective configuration loaded at startup:{}{}",
            System.lineSeparator(), ConfigTreePrinter.print("silicaproxy", properties));
    }
}
