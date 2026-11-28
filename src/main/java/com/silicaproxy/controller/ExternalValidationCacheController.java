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

package com.silicaproxy.controller;

import com.silicaproxy.config.ApiKeyScope;
import com.silicaproxy.config.RequiresApiKey;
import com.silicaproxy.service.decision.ExternalValidationCacheEvictionService;
import com.silicaproxy.service.decision.ExternalValidationCacheEvictionService.EvictionResult;
import org.jspecify.annotations.NullMarked;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code DELETE /api/external-validation/cache?ecosystem=&packageName=&version=} : forgets every
 * external validation result (sync and async state, permanent BLOCKED verdicts, cached ALLOW) of
 * one package version so that the next request re-runs the external services. Idempotent : 200
 * with the number of rows deleted per table, zeros when nothing was cached.
 */
@RestController
@RequestMapping("/api/external-validation/cache")
@NullMarked
public class ExternalValidationCacheController {

    private final ExternalValidationCacheEvictionService evictionService;

    public ExternalValidationCacheController(ExternalValidationCacheEvictionService evictionService) {
        this.evictionService = evictionService;
    }

    @RequiresApiKey(ApiKeyScope.ACTION)
    @DeleteMapping
    public EvictionResult evict(
            @RequestParam String ecosystem,
            @RequestParam String packageName,
            @RequestParam String version) {
        return evictionService.evict(ecosystem, packageName, version);
    }
}
