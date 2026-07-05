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
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
@NullMarked
public class ApiKeyValidator {

    private final SilicaProxyProperties properties;
    private boolean enabled;

    public ApiKeyValidator(SilicaProxyProperties properties) {
        this.properties = properties;
        this.enabled = properties.security().apiAuth().enabled();
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    // ACTION is a superset of READ: the action key also unlocks read-only endpoints, since
    // whoever can trigger a side effect can already observe its result. The read key stays
    // confined to READ endpoints and never unlocks ACTION ones.
    public boolean isAuthorized(ApiKeyScope scope, @Nullable String providedKey) {
        if (!enabled) {
            return true;
        }
        boolean matchesActionKey = constantTimeEquals(properties.security().apiAuth().keyAction(), providedKey);
        if (scope == ApiKeyScope.ACTION) {
            return matchesActionKey;
        }
        return matchesActionKey || constantTimeEquals(properties.security().apiAuth().keyRead(), providedKey);
    }

    // Fails closed (returns false) when no key is configured for the scope: a missing
    // secret must not silently open the endpoint once api-auth is enabled.
    private static boolean constantTimeEquals(@Nullable String expected, @Nullable String actual) {
        if (expected == null || expected.isBlank() || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
