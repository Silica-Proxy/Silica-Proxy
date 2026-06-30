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

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigTreePrinterTest {

    private record Ecosystem(boolean enabled, int minAgeDays) {
    }

    private record Quarantine(boolean enabled, Map<String, Ecosystem> ecosystems) {
    }

    private record Credentials(String apiKey, String url) {
    }

    @Test
    void shouldRenderRecordComponentsInDeclarationOrderAsAsciiTree() {
        Quarantine quarantine = new Quarantine(true, Map.of());

        String tree = ConfigTreePrinter.print("root", quarantine);

        assertThat(tree).isEqualTo(
            "root" + System.lineSeparator()
                + "├── enabled = true" + System.lineSeparator()
                + "└── ecosystems = (none)" + System.lineSeparator());
    }

    @Test
    void shouldRecurseIntoNestedRecordsAndSortMapKeys() {
        Map<String, Ecosystem> ecosystems = new LinkedHashMap<>();
        ecosystems.put("pypi", new Ecosystem(true, 10));
        ecosystems.put("npm", new Ecosystem(true, 7));
        Quarantine quarantine = new Quarantine(true, ecosystems);

        String tree = ConfigTreePrinter.print("root", quarantine);

        assertThat(tree).isEqualTo(
            "root" + System.lineSeparator()
                + "├── enabled = true" + System.lineSeparator()
                + "└── ecosystems" + System.lineSeparator()
                + "    ├── npm" + System.lineSeparator()
                + "    │   ├── enabled = true" + System.lineSeparator()
                + "    │   └── minAgeDays = 7" + System.lineSeparator()
                + "    └── pypi" + System.lineSeparator()
                + "        ├── enabled = true" + System.lineSeparator()
                + "        └── minAgeDays = 10" + System.lineSeparator());
    }

    @Test
    void shouldMaskFieldsThatLookLikeSecrets() {
        Credentials credentials = new Credentials("super-secret-value", "https://example.com");

        String tree = ConfigTreePrinter.print("root", credentials);

        assertThat(tree).contains("apiKey = ****");
        assertThat(tree).doesNotContain("super-secret-value");
        assertThat(tree).contains("url = https://example.com");
    }

    @Test
    void shouldReportBlankAndNullLeafValuesExplicitly() {
        Credentials credentials = new Credentials("", "https://example.com");

        String tree = ConfigTreePrinter.print("root", credentials);

        assertThat(tree).contains("apiKey = (empty)");
    }
}
