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


package com.silicaproxy.service.interception;

import org.jspecify.annotations.NullMarked;

/**
 * Package coordinates extracted from an intercepted request by {@link UrlParserService} or
 * {@link NpmPackumentIndex}. Any part the request does not reveal is {@link #UNKNOWN}.
 */
@NullMarked
public record ParsedPackage(String packageName, String version, String ecosystem) {

    /** Placeholder for any part (ecosystem, name, version) the URL does not reveal. */
    public static final String UNKNOWN = "unknown";

    /** A resource of {@code ecosystem} (possibly {@link #UNKNOWN}) naming no package version. */
    public static ParsedPackage unknown(String ecosystem) {
        return new ParsedPackage(UNKNOWN, UNKNOWN, ecosystem);
    }

    public boolean hasEcosystem() {
        return !UNKNOWN.equals(ecosystem);
    }

    /** Ecosystem, name and version all known : the only case a security decision can be made on. */
    public boolean isIdentified() {
        return hasEcosystem() && !UNKNOWN.equals(packageName) && !UNKNOWN.equals(version);
    }
}
