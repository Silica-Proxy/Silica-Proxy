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
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Case-insensitive checks on the client request headers, shared by the per-ecosystem client
 * detections of {@link NpmUrlParser}, {@link PypiUrlParser} and {@link MavenUrlParser}, and
 * the client identity of the audit log ({@link ClientIdentityResolver}). Every expected value and
 * prefix is given in lower case.
 */
@NullMarked
final class ClientHeaders {

    private static final String BASIC_PREFIX = "Basic ";

    private ClientHeaders() {
    }

    static boolean acceptContains(HttpHeaders headers, String mediaType) {
        String accept = headers.getFirst(HttpHeaders.ACCEPT);
        return accept != null && accept.toLowerCase(Locale.ROOT).contains(mediaType);
    }

    static boolean userAgentStartsWith(HttpHeaders headers, List<String> prefixes) {
        String userAgent = headers.getFirst(HttpHeaders.USER_AGENT);
        return userAgent != null && startsWithAny(userAgent.toLowerCase(Locale.ROOT), prefixes);
    }

    static boolean hasHeaderNameStartingWith(HttpHeaders headers, List<String> prefixes) {
        return headers.headerNames().stream()
                .anyMatch(name -> startsWithAny(name.toLowerCase(Locale.ROOT), prefixes));
    }

    /**
     * Username of a {@code Basic} (Proxy-)Authorization value ; the password is dropped here and
     * never leaves this method. Null for any other scheme (Bearer, Negotiate… carry no username),
     * a malformed value, or a username holding control characters (not a genuine username, and it
     * would be written as is to the audit log).
     */
    static @Nullable String basicAuthUser(@Nullable String authorization) {
        if (authorization == null) {
            return null;
        }
        String value = authorization.strip();
        if (value.length() <= BASIC_PREFIX.length()
                || !value.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            return null;
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(value.substring(BASIC_PREFIX.length()).strip()),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        // RFC 7617 user-id ":" password : without the colon the value may well be a bare secret.
        int colon = decoded.indexOf(':');
        if (colon <= 0) {
            return null;
        }
        String user = decoded.substring(0, colon);
        if (user.isBlank() || user.chars().anyMatch(Character::isISOControl)) {
            return null;
        }
        return user;
    }

    private static boolean startsWithAny(String value, List<String> prefixes) {
        return prefixes.stream().anyMatch(value::startsWith);
    }
}
