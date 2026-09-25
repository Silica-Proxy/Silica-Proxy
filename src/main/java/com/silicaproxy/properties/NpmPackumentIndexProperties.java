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

import jakarta.validation.constraints.Min;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Tuning of {@link com.silicaproxy.service.interception.NpmPackumentIndex}. Kept as its own
 * {@code @ConfigurationProperties} record (not nested in {@link SilicaProxyProperties}) so the
 * feature can be tuned without touching the main record's constructor signature.
 */
@ConfigurationProperties(prefix = "silicaproxy.npm-packument-index")
@Validated
@NullMarked
public record NpmPackumentIndexProperties(
    @DefaultValue("true") boolean enabled,
    // Hard cap on the number of tarball URLs remembered, on top of the TTL : one abbreviated
    // packument of a popular package holds several hundred versions.
    @DefaultValue("200000") @Min(1) int maxEntries,
    // A client resolves the packument then fetches the tarball within seconds ; the TTL only
    // has to cover slow resolutions and retries.
    @DefaultValue("60") @Min(1) int ttlMinutes,
    // Packument bodies bigger than this are relayed untouched and not indexed : a full
    // (non-abbreviated) packument of a huge package can weigh tens of megabytes.
    @DefaultValue("33554432") @Min(1024) long maxBodyBytes,
    // npm tarball request whose package/version could be identified neither from its URL nor
    // from a relayed packument : ALLOW relays it unchecked (bypass), BLOCK answers 403.
    @DefaultValue("ALLOW") UnidentifiedTarballAction unidentifiedTarballAction
) {
    @ConstructorBinding
    public NpmPackumentIndexProperties {
        // canonical constructor, the one bound by Spring
    }

    public enum UnidentifiedTarballAction { ALLOW, BLOCK }
}
