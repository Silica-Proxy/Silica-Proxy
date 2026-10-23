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

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.regex.Pattern;

/**
 * Who downloaded a package, recorded in the audit log so an incident (malware allowed, then
 * flagged) can be traced back to the workstations or CI runners that fetched it. Every part is
 * best effort and self-declared by the client except {@code clientIp}, and each one is truncated
 * to the length of its {@code proxy_audit_logs} column.
 *
 * @param clientIp the client address (see {@code ClientIdentityResolver} for X-Forwarded-For)
 * @param userAgent the client User-Agent (npm/10.x, pip/24, Apache-Maven/3.9…)
 * @param clientId the {@code X-Silica-Client} header, else the Proxy-Authorization username
 *        (never the credential itself)
 */
@NullMarked
public record ClientIdentity(@Nullable String clientIp, @Nullable String userAgent, @Nullable String clientId) {

    // Column lengths of V20__add_client_identity_to_audit_logs.sql
    public static final int MAX_CLIENT_IP_LENGTH = 64;
    public static final int MAX_USER_AGENT_LENGTH = 512;
    public static final int MAX_CLIENT_ID_LENGTH = 255;

    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("[\\p{Cntrl}\\u0080-\\u009F]");

    public static final ClientIdentity UNKNOWN = new ClientIdentity(null, null, null);

    public ClientIdentity {
        clientIp = truncate(clientIp, MAX_CLIENT_IP_LENGTH);
        userAgent = truncate(userAgent, MAX_USER_AGENT_LENGTH);
        clientId = truncate(clientId, MAX_CLIENT_ID_LENGTH);
    }

    // Control characters (NUL is rejected by PostgreSQL, CR/LF forge log lines) become spaces and
    // blank values are dropped. A cut never splits a surrogate pair, and PostgreSQL VARCHAR(n)
    // counts code points, so n UTF-16 chars always fit.
    private static @Nullable String truncate(@Nullable String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String trimmed = CONTROL_CHARACTERS.matcher(value).replaceAll(" ").strip();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (trimmed.length() <= maxLength) {
            return trimmed;
        }
        int end = Character.isHighSurrogate(trimmed.charAt(maxLength - 1)) ? maxLength - 1 : maxLength;
        return trimmed.substring(0, end);
    }
}
