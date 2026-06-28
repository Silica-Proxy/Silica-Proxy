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

import org.jspecify.annotations.NullMarked;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Evaluates if a host matches the {@code non-proxy-hosts} list (standard Java format, hosts
 * separated by '|', wildcard '*' supported), shared between {@link NonProxyAwareProxySelector}
 * (Spring HTTP clients) and JGit configuration (Git clients).
 */
@NullMarked
public final class NonProxyHostMatcher {

    private final List<Pattern> patterns;

    public NonProxyHostMatcher(String nonProxyHosts) {
        this.patterns = parse(nonProxyHosts);
    }

    public boolean matches(String host) {
        return patterns.stream().anyMatch(pattern -> pattern.matcher(host).matches());
    }

    private static List<Pattern> parse(String nonProxyHosts) {
        if (nonProxyHosts.isBlank()) {
            return List.of();
        }
        return Arrays.stream(nonProxyHosts.split("\\|"))
                .map(String::trim)
                .filter(host -> !host.isEmpty())
                .map(NonProxyHostMatcher::toPattern)
                .toList();
    }

    private static Pattern toPattern(String hostPattern) {
        String[] segments = hostPattern.split("\\*", -1);
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(segments[i]));
        }
        return Pattern.compile(regex.toString());
    }
}
