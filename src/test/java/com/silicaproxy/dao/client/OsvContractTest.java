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


package com.silicaproxy.dao.client;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class OsvContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void verifyOsvSeveritySchemaContract() throws Exception {
        Assumptions.assumeTrue(isOsvReachable(), "OSV API is not reachable");

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String requestBody = """
                {
                  "package": {
                    "name": "jinja2",
                    "ecosystem": "PyPI"
                  },
                  "version": "2.11.1"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.osv.dev/v1/query"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        JsonNode root = objectMapper.readTree(response.body());
        assertThat(root.has("vulns")).isTrue();
        
        JsonNode vulns = root.get("vulns");
        assertThat(vulns.isArray()).isTrue();
        assertThat(vulns.size()).isGreaterThan(0);

        boolean severityVerified = false;
        for (JsonNode vuln : vulns) {
            if (vuln.has("severity")) {
                JsonNode severity = vuln.get("severity");
                assertThat(severity.isArray()).isTrue();
                for (JsonNode sev : severity) {
                    assertThat(sev.has("type")).isTrue();
                    assertThat(sev.has("score")).isTrue();
                    String type = sev.get("type").asText();
                    String score = sev.get("score").asText();
                    assertThat(type).startsWith("CVSS_");
                    assertThat(score).startsWith("CVSS:");
                    severityVerified = true;
                }
            }
        }
        assertThat(severityVerified).as("At least one vulnerability must have a parsed severity field").isTrue();
    }

    private boolean isOsvReachable() {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(2))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.osv.dev/v1/query"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .timeout(Duration.ofSeconds(2))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200 || response.statusCode() == 400;
        } catch (Exception e) {
            return false;
        }
    }
}
