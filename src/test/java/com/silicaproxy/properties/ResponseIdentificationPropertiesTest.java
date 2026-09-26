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

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ResponseIdentificationPropertiesTest {

    private static ResponseIdentificationProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("silicaproxy.response-identification", ResponseIdentificationProperties.class);
    }

    @Test
    void shouldBeEnabledByDefault() {
        assertThat(bind(Map.of()).enabled()).isTrue();
    }

    @Test
    void shouldBindDisabled() {
        assertThat(bind(Map.of("silicaproxy.response-identification.enabled", "false")).enabled()).isFalse();
    }
}
