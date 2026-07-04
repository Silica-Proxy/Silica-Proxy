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

import org.jspecify.annotations.NullMarked;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validates regular expressions for safety to prevent ReDoS (Regular Expression Denial of Service) attacks.
 * This validator checks for patterns that could cause catastrophic backtracking in regex engines.
 */
@NullMarked
public final class RegexValidator {

    /**
     * Maximum allowed length for a regex pattern to prevent excessively complex patterns.
     */
    public static final int MAX_PATTERN_LENGTH = 256;

    /**
     * Pattern to detect adjacent + or * quantifiers which can cause exponential backtracking.
     * Matches patterns like ++, **, +*, *+, etc.
     */
    private static final Pattern ADJACENT_QUANTIFIERS = Pattern.compile(
            "[+*][+*]"
    );

    /**
     * Pattern to detect nested quantifiers - groups with quantifiers that are themselves quantified.
     * Matches patterns like (a+)+, (a*)+, (a+)*, ((a+))+, etc.
     */
    private static final Pattern NESTED_QUANTIFIERS_PATTERN = Pattern.compile(
            "\\([^()]*[+*?][^()]*\\)[+*?]"
    );

    private RegexValidator() {
        // Utility class - prevent instantiation
    }

    /**
     * Validates a regex pattern for safety.
     *
     * @param pattern the regex pattern to validate
     * @return the compiled Pattern if valid
     * @throws PatternSyntaxException if the pattern has syntax errors
     * @throws IllegalArgumentException if the pattern is unsafe (potential ReDoS)
     */
    public static Pattern validateAndCompile(String pattern) throws PatternSyntaxException {
        if (pattern == null) {
            throw new IllegalArgumentException("Pattern cannot be null");
        }

        // Check length
        if (pattern.length() > MAX_PATTERN_LENGTH) {
            throw new IllegalArgumentException(
                    "Pattern exceeds maximum length of " + MAX_PATTERN_LENGTH + " characters");
        }

        // Check for null/empty after trimming
        String trimmed = pattern.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Pattern cannot be empty");
        }

        // Check for dangerous patterns
        checkForDangerousPatterns(trimmed);

        // Compile to verify syntax
        return Pattern.compile(trimmed);
    }

    /**
     * Validates a regex pattern string without compiling it.
     * Useful when the pattern will be used in a different regex engine (e.g., PostgreSQL).
     *
     * @param pattern the regex pattern to validate
     * @throws IllegalArgumentException if the pattern is unsafe (potential ReDoS) or invalid
     */
    public static void validatePattern(String pattern) {
        if (pattern == null) {
            throw new IllegalArgumentException("Pattern cannot be null");
        }

        // Check length
        if (pattern.length() > MAX_PATTERN_LENGTH) {
            throw new IllegalArgumentException(
                    "Pattern exceeds maximum length of " + MAX_PATTERN_LENGTH + " characters");
        }

        // Check for null/empty after trimming
        String trimmed = pattern.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Pattern cannot be empty");
        }

        // Check for dangerous patterns
        checkForDangerousPatterns(trimmed);

        // Verify syntax
        try {
            Pattern.compile(trimmed);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regex syntax: " + e.getMessage(), e);
        }
    }

    /**
     * Checks for patterns that could cause ReDoS attacks.
     *
     * @param pattern the pattern to check
     * @throws IllegalArgumentException if a dangerous pattern is detected
     */
    private static void checkForDangerousPatterns(String pattern) {
        // Check for adjacent + or * quantifiers
        if (ADJACENT_QUANTIFIERS.matcher(pattern).find()) {
            throw new IllegalArgumentException(
                    "Adjacent quantifiers detected (e.g., a++, a**, etc.) which can cause ReDoS");
        }

        // Check for nested quantifiers - primary cause of ReDoS
        if (NESTED_QUANTIFIERS_PATTERN.matcher(pattern).find()) {
            throw new IllegalArgumentException(
                    "Nested quantifiers detected (e.g., (a+)+, (a*)+, etc.) which can cause ReDoS");
        }
    }
}
