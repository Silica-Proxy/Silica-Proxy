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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ParsedPackageTest {

    @Test
    void shouldBuildUnknownPackageOfGivenEcosystem() {
        assertThat(ParsedPackage.unknown("npm")).isEqualTo(new ParsedPackage("unknown", "unknown", "npm"));
    }

    @Test
    void shouldReportEcosystemPresence() {
        assertThat(ParsedPackage.unknown("maven").hasEcosystem()).isTrue();
        assertThat(ParsedPackage.unknown(ParsedPackage.UNKNOWN).hasEcosystem()).isFalse();
    }

    @Test
    void shouldBeIdentifiedOnlyWhenEcosystemNameAndVersionAreAllKnown() {
        assertThat(new ParsedPackage("lodash", "4.17.21", "npm").isIdentified()).isTrue();
        assertThat(new ParsedPackage("lodash", "unknown", "npm").isIdentified()).isFalse();
        assertThat(new ParsedPackage("unknown", "4.17.21", "npm").isIdentified()).isFalse();
        assertThat(new ParsedPackage("lodash", "4.17.21", "unknown").isIdentified()).isFalse();
    }
}
