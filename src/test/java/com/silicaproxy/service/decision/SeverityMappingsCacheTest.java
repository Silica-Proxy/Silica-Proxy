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


package com.silicaproxy.service.decision;

import com.silicaproxy.dao.policy.DecisionDao;
import com.silicaproxy.model.entity.SeverityMapping;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SeverityMappingsCacheTest {

    @Test
    void shouldExposeMappingsAfterInit() {
        DecisionDao decisionDao = mock(DecisionDao.class);
        when(decisionDao.findAllSeverityMappings()).thenReturn(List.of(
                new SeverityMapping("HIGH", 7.0, 8.9)
        ));

        SeverityMappingsCache cache = new SeverityMappingsCache(decisionDao);
        cache.refresh();

        assertThat(cache.get("HIGH")).isNotNull();
        assertThat(cache.get("HIGH").minCvss()).isEqualTo(7.0);
    }

    @Test
    void shouldReturnNullForUnknownSeverityLevel() {
        DecisionDao decisionDao = mock(DecisionDao.class);
        when(decisionDao.findAllSeverityMappings()).thenReturn(List.of());

        SeverityMappingsCache cache = new SeverityMappingsCache(decisionDao);
        cache.refresh();

        assertThat(cache.get("CRITICAL")).isNull();
    }

    @Test
    void shouldReplaceValuesOnRefresh() {
        DecisionDao decisionDao = mock(DecisionDao.class);
        when(decisionDao.findAllSeverityMappings())
                .thenReturn(List.of(new SeverityMapping("HIGH", 7.0, 8.9)))
                .thenReturn(List.of(new SeverityMapping("HIGH", 5.0, 8.9)));

        SeverityMappingsCache cache = new SeverityMappingsCache(decisionDao);
        cache.refresh();
        assertThat(cache.get("HIGH").minCvss()).isEqualTo(7.0);

        cache.refresh();
        assertThat(cache.get("HIGH").minCvss()).isEqualTo(5.0);
    }

    @Test
    void shouldKeepPreviousValuesWhenRefreshFails() {
        DecisionDao decisionDao = mock(DecisionDao.class);
        when(decisionDao.findAllSeverityMappings())
                .thenReturn(List.of(new SeverityMapping("HIGH", 7.0, 8.9)))
                .thenThrow(new RuntimeException("DB unavailable"));

        SeverityMappingsCache cache = new SeverityMappingsCache(decisionDao);
        cache.refresh();
        assertThat(cache.get("HIGH").minCvss()).isEqualTo(7.0);

        // A transient failure must not wipe the previously loaded, still-valid mapping.
        cache.refresh();
        assertThat(cache.get("HIGH").minCvss()).isEqualTo(7.0);
    }
}
