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

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler exceptionHandler = new GlobalExceptionHandler();

    @Test
    void shouldReturn400OnIllegalArgument() {
        IllegalArgumentException exception = new IllegalArgumentException("Invalid parameter");
        
        ProblemDetail result = exceptionHandler.handleIllegalArgument(exception);
        
        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getDetail()).isEqualTo("Invalid parameter");
    }

    @Test
    void shouldReturn500OnUnexpectedException() {
        RuntimeException exception = new RuntimeException("Unexpected error");
        
        ProblemDetail result = exceptionHandler.handleUnexpected(exception);
        
        assertThat(result.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(result.getDetail()).isEqualTo("An internal error occurred.");
    }

    @Test
    void shouldReturn400OnMissingParam() {
        MissingServletRequestParameterException exception = 
                new MissingServletRequestParameterException("packageName", "string");
        
        ProblemDetail result = exceptionHandler.handleMissingParam(exception);
        
        assertThat(result.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(result.getDetail()).contains("packageName");
        assertThat(result.getDetail()).contains("required");
    }

    @Test
    void shouldReturn405OnMethodNotSupported() {
        HttpRequestMethodNotSupportedException exception = 
                new HttpRequestMethodNotSupportedException("GET");
        
        ProblemDetail result = exceptionHandler.handleMethodNotSupported(exception);
        
        assertThat(result.getStatus()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED.value());
    }
}
