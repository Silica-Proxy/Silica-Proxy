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

import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Downloads lists of modified OSV advisories ({@code modified_id.csv}) and individual JSONs 
 * from the public OSV GCS bucket. Called exclusively by {@code OsvIncrementalSyncService}
 * during the hourly update cycle.
 */
@Component
@NullMarked
public class OsvIncrementalClient {

    private static final Logger LOG = LoggerFactory.getLogger(OsvIncrementalClient.class);

    private final RestClient restClient;

    public OsvIncrementalClient(
            @Qualifier("registriesRequestFactory") ClientHttpRequestFactory registriesRequestFactory,
            com.silicaproxy.config.SsrfInterceptor ssrfInterceptor) {
        this.restClient = RestClient.builder()
                .requestFactory(registriesRequestFactory)
                .requestInterceptor(ssrfInterceptor)
                .build();
    }

    /**
     * Reads {@code modified_id.csv} for an OSV ecosystem and returns the IDs of advisories 
     * published or modified after {@code since}. The CSV is sorted from most recent to oldest : 
     * reading stops at the first line whose timestamp is before or equal to {@code since}, 
     * without going through the entire file.
     */
    @Timed(value = "silicaproxy.dao.osv.incremental.fetchids",
            description = "Duration of downloading and filtering OSV modified_id.csv")
    public List<String> fetchModifiedIdsSince(String gcsBaseUrl, String ecosystemPath, Instant since) {
        String url = gcsBaseUrl + "/" + ecosystemPath + "/modified_id.csv";
        String csv = restClient.get().uri(url).retrieve().body(String.class);

        List<String> ids = new ArrayList<>();
        if (csv == null || csv.isBlank()) {
            return ids;
        }

        for (String line : csv.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int comma = trimmed.indexOf(',');
            if (comma < 0) {
                continue;
            }
            try {
                Instant modified = Instant.parse(trimmed.substring(0, comma));
                if (!modified.isAfter(since)) {
                    break;
                }
                ids.add(trimmed.substring(comma + 1));
            } catch (Exception e) {
                LOG.warn("OSV CSV line ignored (invalid format) : {}", trimmed);
            }
        }
        return ids;
    }

    /**
     * Downloads the JSON of an individual OSV advisory from GCS.
     * Returns an empty string in case of HTTP error.
     */
    @Timed(value = "silicaproxy.dao.osv.incremental.fetchjson",
            description = "Duration of downloading an individual OSV advisory")
    public String fetchAdvisoryJson(String gcsBaseUrl, String ecosystemPath, String id) {
        String url = gcsBaseUrl + "/" + ecosystemPath + "/" + id + ".json";
        String json = restClient.get().uri(url).retrieve().body(String.class);
        return json != null ? json : "";
    }
}
