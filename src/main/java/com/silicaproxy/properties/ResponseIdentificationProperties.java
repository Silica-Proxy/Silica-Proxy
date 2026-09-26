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

import org.jspecify.annotations.NullMarked;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Tuning of {@link com.silicaproxy.service.interception.ResponseIdentificationService}. Kept as its
 * own {@code @ConfigurationProperties} record, like {@link NpmPackumentIndexProperties}.
 */
@ConfigurationProperties(prefix = "silicaproxy.response-identification")
@Validated
@NullMarked
public record ResponseIdentificationProperties(
    // false : no digest lookup at all (no database read, no deps.dev call), requests the URL does
    // not identify are relayed unchecked.
    @DefaultValue("true") boolean enabled
) {
    @ConstructorBinding
    public ResponseIdentificationProperties {
        // canonical constructor, the one bound by Spring
    }
}
