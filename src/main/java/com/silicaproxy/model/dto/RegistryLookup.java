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

import java.util.Optional;
import org.jspecify.annotations.NullMarked;

// Outcome of a public registry lookup (RegistryClient.lookupNpmPublic) that, unlike a bare
// Optional, tells "the registry does not know this package/version" (NOT_FOUND : falling back
// to another source is legitimate) apart from "the registry could not answer" (UNAVAILABLE :
// no fallback to a less trusted source, the fail-open/fail-closed policy decides instead).
@NullMarked
public record RegistryLookup(Status status, Optional<PackageMetadataResult> metadata) {

    public enum Status { FOUND, NOT_FOUND, UNAVAILABLE }

    public static RegistryLookup found(PackageMetadataResult metadata) {
        return new RegistryLookup(Status.FOUND, Optional.of(metadata));
    }

    public static RegistryLookup notFound() {
        return new RegistryLookup(Status.NOT_FOUND, Optional.empty());
    }

    public static RegistryLookup unavailable() {
        return new RegistryLookup(Status.UNAVAILABLE, Optional.empty());
    }
}
