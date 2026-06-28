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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NonProxyHostMatcherTest {

    @Test
    void shouldMatchExactHostsInPipeSeparatedList() {
        NonProxyHostMatcher matcher = new NonProxyHostMatcher("localhost|127.0.0.1");

        assertThat(matcher.matches("localhost")).isTrue();
        assertThat(matcher.matches("127.0.0.1")).isTrue();
        assertThat(matcher.matches("registry.npmjs.org")).isFalse();
    }

    @Test
    void shouldMatchWildcardSuffixPattern() {
        NonProxyHostMatcher matcher = new NonProxyHostMatcher("*.internal.corp");

        assertThat(matcher.matches("gitea.internal.corp")).isTrue();
        assertThat(matcher.matches("policies.gitea.internal.corp")).isTrue();
        assertThat(matcher.matches("internal.corp")).isFalse();
        assertThat(matcher.matches("example.com")).isFalse();
    }

    @Test
    void shouldTreatDotsAsLiteralNotRegexWildcard() {
        // "127.0.0.1" must not match a arbitrary host because '.' interpreted as
        // wildcard regex (ex: "127x0x0x1" must not match).
        NonProxyHostMatcher matcher = new NonProxyHostMatcher("127.0.0.1");

        assertThat(matcher.matches("127.0.0.1")).isTrue();
        assertThat(matcher.matches("127x0x0x1")).isFalse();
    }

    @Test
    void shouldReturnFalseForEveryHostWhenConfigIsBlank() {
        NonProxyHostMatcher matcher = new NonProxyHostMatcher("");

        assertThat(matcher.matches("localhost")).isFalse();
        assertThat(matcher.matches("anything.example.com")).isFalse();
    }

    @Test
    void shouldTrimWhitespaceAroundEachPipeSeparatedEntry() {
        NonProxyHostMatcher matcher = new NonProxyHostMatcher(" localhost | 127.0.0.1 ");

        assertThat(matcher.matches("localhost")).isTrue();
        assertThat(matcher.matches("127.0.0.1")).isTrue();
    }
}
