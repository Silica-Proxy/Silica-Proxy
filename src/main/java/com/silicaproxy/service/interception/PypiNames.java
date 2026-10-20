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

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * PyPI project name normalization (PEP 503) : PyPI treats {@code PyYAML}, {@code pyyaml} and
 * {@code py_yaml} as the same project, while file names keep the spelling of the upload
 * ({@code PyYAML-6.0.2-...whl}, {@code typing_extensions-4.12.2-...whl}) and OSV stores the
 * normalized one ({@code pyyaml}). Every PyPI name the proxy compares (URL, OSV advisory,
 * GitOps rule) goes through {@link #normalize} first so that they all match.
 */
@NullMarked
public final class PypiNames {

    private static final Pattern SEPARATORS = Pattern.compile("[-_.]+");

    private PypiNames() {
    }

    /** {@code re.sub(r"[-_.]+", "-", name).lower()}, as defined by PEP 503. */
    public static String normalize(String name) {
        return SEPARATORS.matcher(name).replaceAll("-").toLowerCase(Locale.ROOT);
    }
}
