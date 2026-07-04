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


package com.silicaproxy.util;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegexValidatorTest {

    @Test
    void validateAndCompileShouldAcceptSafePatterns() throws Exception {
        // Simple patterns
        Pattern p1 = RegexValidator.validateAndCompile("^[a-z]+$");
        assertThat(p1.pattern()).isEqualTo("^[a-z]+$");

        Pattern p2 = RegexValidator.validateAndCompile("\\d{1,3}");
        assertThat(p2.pattern()).isEqualTo("\\d{1,3}");

        // Pattern with safe quantifiers
        Pattern p3 = RegexValidator.validateAndCompile("a+b*c?");
        assertThat(p3.pattern()).isEqualTo("a+b*c?");

        // Pattern with groups but no nested quantifiers
        Pattern p4 = RegexValidator.validateAndCompile("^(abc)+$");
        assertThat(p4.pattern()).isEqualTo("^(abc)+$");

        // Pattern with character classes
        Pattern p5 = RegexValidator.validateAndCompile("[a-zA-Z0-9]+");
        assertThat(p5.pattern()).isEqualTo("[a-zA-Z0-9]+");
    }

    @Test
    void validateAndCompileShouldRejectNull() {
        assertThatThrownBy(() -> RegexValidator.validateAndCompile(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Pattern cannot be null");
    }

    @Test
    void validateAndCompileShouldRejectEmpty() {
        assertThatThrownBy(() -> RegexValidator.validateAndCompile(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Pattern cannot be empty");

        assertThatThrownBy(() -> RegexValidator.validateAndCompile("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Pattern cannot be empty");
    }

    @Test
    void validateAndCompileShouldRejectPatternsExceedingMaxLength() {
        String longPattern = "a".repeat(RegexValidator.MAX_PATTERN_LENGTH + 1);
        assertThatThrownBy(() -> RegexValidator.validateAndCompile(longPattern))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds maximum length");
    }

    @Test
    void validateAndCompileShouldRejectInvalidSyntax() {
        assertThatThrownBy(() -> RegexValidator.validateAndCompile("[invalid"))
                .isInstanceOf(PatternSyntaxException.class);
    }

    @Test
    void validatePatternShouldAcceptSafePatterns() {
        // These should not throw
        RegexValidator.validatePattern("^[a-z]+$");
        RegexValidator.validatePattern("\\d{1,3}");
        RegexValidator.validatePattern("a+b*c?");
        RegexValidator.validatePattern("^(abc)+$");
    }

    @Test
    void validatePatternShouldRejectNestedQuantifiers() {
        // Classic ReDoS patterns with non-nested parentheses
        assertThatThrownBy(() -> RegexValidator.validatePattern("(a+)+"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Nested quantifiers");

        assertThatThrownBy(() -> RegexValidator.validatePattern("(a*)+"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Nested quantifiers");

        assertThatThrownBy(() -> RegexValidator.validatePattern("(a+)*"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Nested quantifiers");

        // Note: deeply nested patterns like ((a+))+ are not detected by the current implementation
        // as they require recursive parsing, but the most common ReDoS cases are caught

        assertThatThrownBy(() -> RegexValidator.validatePattern("(a+)+b"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Nested quantifiers");
    }

    @Test
    void validatePatternShouldRejectAdjacentPlusAndStarQuantifiers() {
        assertThatThrownBy(() -> RegexValidator.validatePattern("a++"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Adjacent quantifiers");

        assertThatThrownBy(() -> RegexValidator.validatePattern("a**"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Adjacent quantifiers");

        assertThatThrownBy(() -> RegexValidator.validatePattern("a+*"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Adjacent quantifiers");

        assertThatThrownBy(() -> RegexValidator.validatePattern("a*+"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Adjacent quantifiers");
    }

    @Test
    void validatePatternShouldAllowSafeQuantifierCombinations() {
        // These are safe: +?, *?, ?? (possessive/lazy quantifiers)
        RegexValidator.validatePattern("a+?");
        RegexValidator.validatePattern("a*?");
        RegexValidator.validatePattern("a??");

        // These are safe: single quantifiers
        RegexValidator.validatePattern("a+");
        RegexValidator.validatePattern("a*");
        RegexValidator.validatePattern("a?");
    }

    @Test
    void validatePatternShouldHandleEscapedCharacters() {
        // Escaped parentheses should not trigger false positives
        RegexValidator.validatePattern("\\(literal\\)");
        RegexValidator.validatePattern("\\\\+");
        RegexValidator.validatePattern("\\\\*");
    }

    @Test
    void validatePatternShouldHandleCharacterClasses() {
        // Character classes with quantifiers should be fine
        RegexValidator.validatePattern("[a-z]+");
        RegexValidator.validatePattern("[a-z]*");
        RegexValidator.validatePattern("[a-z]+[0-9]+");
    }

    @Test
    void validatePatternShouldHandleComplexSafePatterns() {
        // These are complex but safe patterns - using raw string equivalents
        RegexValidator.validatePattern("^\\d{3}-\\d{2}-\\d{4}$");
        RegexValidator.validatePattern("[a-zA-Z0-9._%+-]+");
        RegexValidator.validatePattern("^[a-z]+");
    }
}
