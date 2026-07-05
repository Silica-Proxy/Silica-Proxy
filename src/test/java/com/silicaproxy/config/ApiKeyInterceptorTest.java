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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.method.HandlerMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ApiKeyInterceptorTest {

    @Mock
    private ApiKeyValidator apiKeyValidator;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private ApiKeyInterceptor interceptor;

    private static class SampleController {
        @RequiresApiKey(ApiKeyScope.READ)
        void readMethod() {
        }

        void unannotatedMethod() {
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        interceptor = new ApiKeyInterceptor(apiKeyValidator);
    }

    private static HandlerMethod handlerMethodFor(String methodName) throws NoSuchMethodException {
        SampleController controller = new SampleController();
        return new HandlerMethod(controller, SampleController.class.getDeclaredMethod(methodName));
    }

    @Test
    void shouldPassThroughWhenHandlerIsNotAnnotated() throws Exception {
        boolean result = interceptor.preHandle(request, response, handlerMethodFor("unannotatedMethod"));

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void shouldPassThroughWhenHandlerIsNotAHandlerMethod() {
        boolean result = interceptor.preHandle(request, response, new Object());

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void shouldAllowRequestWithValidKey() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer good-key");
        when(apiKeyValidator.isAuthorized(ApiKeyScope.READ, "good-key")).thenReturn(true);

        boolean result = interceptor.preHandle(request, response, handlerMethodFor("readMethod"));

        assertThat(result).isTrue();
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void shouldRejectRequestWithInvalidKey() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer bad-key");
        when(apiKeyValidator.isAuthorized(ApiKeyScope.READ, "bad-key")).thenReturn(false);

        boolean result = interceptor.preHandle(request, response, handlerMethodFor("readMethod"));

        assertThat(result).isFalse();
        verify(response).setStatus(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void shouldRejectRequestWithMissingAuthorizationHeader() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(apiKeyValidator.isAuthorized(ApiKeyScope.READ, null)).thenReturn(false);

        boolean result = interceptor.preHandle(request, response, handlerMethodFor("readMethod"));

        assertThat(result).isFalse();
        verify(response).setStatus(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void shouldRejectRequestWithMalformedAuthorizationHeader() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic dXNlcjpwYXNz");
        when(apiKeyValidator.isAuthorized(ApiKeyScope.READ, null)).thenReturn(false);

        boolean result = interceptor.preHandle(request, response, handlerMethodFor("readMethod"));

        assertThat(result).isFalse();
        verify(response).setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}
