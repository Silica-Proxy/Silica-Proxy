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

import java.util.Locale;
import org.jspecify.annotations.NullMarked;

/** File digest algorithms an upstream registry announces and deps.dev can be queried with. */
@NullMarked
public enum HashType {
    SHA1("SHA-1", 40),
    SHA256("SHA-256", 64);

    private final String algorithm;
    private final int hexLength;

    HashType(String algorithm, int hexLength) {
        this.algorithm = algorithm;
        this.hexLength = hexLength;
    }

    /** {@link java.security.MessageDigest} algorithm name. */
    public String algorithm() {
        return algorithm;
    }

    /** Whether {@code value} is a digest of this type : exactly the right number of hex digits. */
    public boolean isValidHex(String value) {
        if (value.length() != hexLength) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (Character.digit(value.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    /** Lower-case form, the one digests are compared and cached on. */
    public static String normalizeHex(String value) {
        return value.toLowerCase(Locale.ROOT);
    }
}
