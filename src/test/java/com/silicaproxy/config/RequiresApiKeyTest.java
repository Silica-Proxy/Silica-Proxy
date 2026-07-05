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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class RequiresApiKeyTest {

    private static class SampleController {
        @RequiresApiKey(ApiKeyScope.READ)
        void readMethod() {
        }

        @RequiresApiKey(ApiKeyScope.ACTION)
        void actionMethod() {
        }

        void unannotatedMethod() {
        }
    }

    @Test
    void shouldBeRetainedAtRuntimeAndTargetMethods() {
        Retention retention = RequiresApiKey.class.getAnnotation(Retention.class);
        assertThat(retention.value()).isEqualTo(RetentionPolicy.RUNTIME);

        java.lang.annotation.Target target = RequiresApiKey.class.getAnnotation(java.lang.annotation.Target.class);
        assertThat(target.value()).containsExactly(ElementType.METHOD);
    }

    @Test
    void shouldExposeConfiguredScopeOnAnnotatedMethod() throws NoSuchMethodException {
        Method readMethod = SampleController.class.getDeclaredMethod("readMethod");
        Method actionMethod = SampleController.class.getDeclaredMethod("actionMethod");
        Method unannotatedMethod = SampleController.class.getDeclaredMethod("unannotatedMethod");

        assertThat(readMethod.getAnnotation(RequiresApiKey.class).value()).isEqualTo(ApiKeyScope.READ);
        assertThat(actionMethod.getAnnotation(RequiresApiKey.class).value()).isEqualTo(ApiKeyScope.ACTION);
        assertThat(unannotatedMethod.getAnnotation(RequiresApiKey.class)).isNull();
    }
}
