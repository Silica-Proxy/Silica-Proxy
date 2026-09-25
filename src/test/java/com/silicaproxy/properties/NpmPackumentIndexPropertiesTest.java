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

import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class NpmPackumentIndexPropertiesTest {

    private static NpmPackumentIndexProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("silicaproxy.npm-packument-index", NpmPackumentIndexProperties.class);
    }

    // Moved from NpmPackumentIndexPersistenceTest.shouldExposeUnidentifiedTarballAction, which
    // checked the default through a convenience constructor that no longer exists.
    @Test
    void shouldRelayUnidentifiedTarballsByDefault() {
        assertThat(bind(Map.of()).unidentifiedTarballAction()).isEqualTo(UnidentifiedTarballAction.ALLOW);
    }

    @Test
    void shouldBindBlockAction() {
        assertThat(bind(Map.of("silicaproxy.npm-packument-index.unidentified-tarball-action", "BLOCK"))
                .unidentifiedTarballAction()).isEqualTo(UnidentifiedTarballAction.BLOCK);
    }
}
