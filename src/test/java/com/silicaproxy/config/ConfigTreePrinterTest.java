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

import com.silicaproxy.properties.SilicaProxyProperties.ExternalValidationProperties;
import com.silicaproxy.properties.SilicaProxyProperties.ExternalValidationServiceProperties;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ConfigTreePrinterTest {

    private record Ecosystem(boolean enabled, int minAgeDays) {
    }

    private record Quarantine(boolean enabled, Map<String, Ecosystem> ecosystems) {
    }

    private record Credentials(String apiKey, String url) {
    }

    private record Sections(String first, String second, String third, String fourth) {
    }

    private record Wrapper(Sections nested) {
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

    @Test
    void shouldRenderRealExternalValidationServicesWithMaskedApiKeys() {
        ExternalValidationServiceProperties deepScan = new ExternalValidationServiceProperties(
            true, "https://scanner.example.com/scan", "secret-api-key", "SYNC", 1, true, true, 60, 30);
        ExternalValidationProperties externalValidation = new ExternalValidationProperties(
            "https://proxy.example.com", false, Map.of("deepScan", deepScan));

        String tree = ConfigTreePrinter.print("externalValidation", externalValidation);

        assertThat(tree).contains("callbackBaseUrl = https://proxy.example.com");
        assertThat(tree).contains("deepScan");
        assertThat(tree).contains("apiKey = ****");
        assertThat(tree).doesNotContain("secret-api-key");
        assertThat(tree).contains("mode = SYNC");
    }

    @Test
    void shouldRenderExternalValidationWithNoConfiguredServicesAsNone() {
        ExternalValidationProperties externalValidation = new ExternalValidationProperties("", true, null);

        String tree = ConfigTreePrinter.print("externalValidation", externalValidation);

        assertThat(tree).contains("callbackBaseUrl = (empty)");
        assertThat(tree).contains("services = (none)");
    }

    @Test
    void shouldReorderTopLevelEntriesAccordingToExplicitOrderAndAppendTheRestAfter() {
        Sections sections = new Sections("a", "b", "c", "d");

        String tree = ConfigTreePrinter.print("root", sections, Map.of("root", List.of("third", "first")));

        assertThat(tree).isEqualTo(
            "root" + System.lineSeparator()
                + "├── third = c" + System.lineSeparator()
                + "├── first = a" + System.lineSeparator()
                + "├── second = b" + System.lineSeparator()
                + "└── fourth = d" + System.lineSeparator());
    }

    @Test
    void shouldReorderNestedNodeByLabelRegardlessOfDepth() {
        Wrapper wrapper = new Wrapper(new Sections("a", "b", "c", "d"));

        String tree = ConfigTreePrinter.print("root", wrapper, Map.of("nested", List.of("fourth", "second")));

        assertThat(tree).isEqualTo(
            "root" + System.lineSeparator()
                + "└── nested" + System.lineSeparator()
                + "    ├── fourth = d" + System.lineSeparator()
                + "    ├── second = b" + System.lineSeparator()
                + "    ├── first = a" + System.lineSeparator()
                + "    └── third = c" + System.lineSeparator());
    }

    @Test
    void shouldOverrideDisplayLabelWithoutAffectingOrderingOrSecretDetection() {
        Credentials credentials = new Credentials("super-secret-value", "https://example.com");

        String tree = ConfigTreePrinter.print("root", credentials, Map.of(), Map.of("apiKey", "renamedField"));

        assertThat(tree).contains("renamedField = ****");
        assertThat(tree).doesNotContain("apiKey");
        assertThat(tree).doesNotContain("super-secret-value");
    }
}
