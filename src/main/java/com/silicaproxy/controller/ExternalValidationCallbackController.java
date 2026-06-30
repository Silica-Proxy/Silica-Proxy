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

import com.silicaproxy.model.dto.ExternalValidationCallbackRequest;
import com.silicaproxy.service.decision.ExternalValidationService;
import com.silicaproxy.service.decision.ExternalValidationService.CallbackResult;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/external-validation")
@NullMarked
public class ExternalValidationCallbackController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final ExternalValidationService externalValidationService;

    public ExternalValidationCallbackController(ExternalValidationService externalValidationService) {
        this.externalValidationService = externalValidationService;
    }

    @PostMapping("/callback/{token}")
    public ResponseEntity<Void> callback(
            @PathVariable UUID token,
            @RequestBody ExternalValidationCallbackRequest request,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) @Nullable String authorization) {
        String verdict = request.verdict();
        if (!"ALLOWED".equalsIgnoreCase(verdict) && !"BLOCKED".equalsIgnoreCase(verdict)) {
            return ResponseEntity.badRequest().build();
        }

        String apiKey = extractBearerToken(authorization);
        CallbackResult result =
                externalValidationService.processCallback(token, verdict, request.reason(), apiKey);
        return switch (result) {
            case PROCESSED -> ResponseEntity.ok().build();
            case NOT_FOUND -> ResponseEntity.notFound().build();
            case UNAUTHORIZED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        };
    }

    private static @Nullable String extractBearerToken(@Nullable String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorizationHeader.substring(BEARER_PREFIX.length()).trim();
    }
}
