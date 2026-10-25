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


package com.silicaproxy.model.dto;

import java.time.Instant;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

// Result of a metadata resolution from a public registry (RegistryClient), used 
// for age calculation (quarantine) and deprecation/yanked detection. publishedAt dates the
// requested artifact ; latestPublishedAt is the most recent publication among all the files of
// the version (PyPI releases receive new files over time), equal to publishedAt elsewhere.
@NullMarked
public record PackageMetadataResult(
    Instant publishedAt,
    Instant latestPublishedAt,
    boolean isDeprecated,
    @Nullable String deprecationReason
) {

    public PackageMetadataResult(Instant publishedAt, boolean isDeprecated, @Nullable String deprecationReason) {
        this(publishedAt, publishedAt, isDeprecated, deprecationReason);
    }
}
