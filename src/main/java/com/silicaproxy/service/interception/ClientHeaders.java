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
import org.springframework.http.HttpHeaders;

import java.util.List;
import java.util.Locale;

/**
 * Case-insensitive checks on the client request headers, shared by the per-ecosystem client
 * detections of {@link NpmUrlParser}, {@link PypiUrlParser} and {@link MavenUrlParser}. Every
 * expected value and prefix is given in lower case.
 */
@NullMarked
final class ClientHeaders {

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
        for (String name : headers.headerNames()) {
            if (startsWithAny(name.toLowerCase(Locale.ROOT), prefixes)) {
                return true;
            }
        }
        return false;
    }

    private static boolean startsWithAny(String value, List<String> prefixes) {
        for (String prefix : prefixes) {
            if (value.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
