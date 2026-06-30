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

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Renders a Java record graph (Spring {@code @ConfigurationProperties} beans such as
 * {@link com.silicaproxy.properties.SilicaProxyProperties} are records of records) as an
 * ASCII tree. Record components are walked via reflection in declaration order, so the
 * printed tree always matches the order the configuration is declared in, without needing
 * to be kept in sync by hand whenever a property is added or removed — unless an explicit
 * order or display label is supplied for a given node via
 * {@link #print(String, Object, Map, Map)}, e.g. to reflect the order configuration sections
 * are actually evaluated at runtime rather than where they happen to be declared, or to show
 * a clearer name than the raw property without renaming the property itself. Map entries
 * default to key order since {@code HashMap} does not preserve insertion order. Field names
 * that look like secrets (password/token/api key) are masked rather than printed in clear
 * text.
 */
@NullMarked
public final class ConfigTreePrinter {

    private static final String INDENT_BRANCH = "│   ";
    private static final String INDENT_LAST = "    ";
    private static final String CONNECTOR_BRANCH = "├── ";
    private static final String CONNECTOR_LAST = "└── ";

    private ConfigTreePrinter() {
    }

    /**
     * Builds the ASCII tree for {@code root} (expected to be a record), prefixed by
     * {@code rootLabel} as its top-level node name, in record declaration order.
     */
    public static String print(String rootLabel, Object root) {
        return print(rootLabel, root, Map.of(), Map.of());
    }

    /**
     * Same as {@link #print(String, Object)}, but wherever a node's label matches a key in
     * {@code nodeOrders} (at any depth, including {@code rootLabel} itself), its direct
     * children are reordered to put the entries named in that key's value first, in that
     * order; any child not listed keeps its original relative position, appended after.
     * Nodes whose label has no entry in {@code nodeOrders} keep their default order.
     */
    public static String print(String rootLabel, Object root, Map<String, List<String>> nodeOrders) {
        return print(rootLabel, root, nodeOrders, Map.of());
    }

    /**
     * Same as {@link #print(String, Object, Map)}, but wherever a node's label (the property
     * name) matches a key in {@code labelOverrides}, the mapped value is printed instead.
     * Ordering ({@code nodeOrders} lookups, secret detection) still keys off the original
     * property name, so overriding a display label never affects how that node is sorted or
     * masked.
     */
    public static String print(
            String rootLabel, Object root, Map<String, List<String>> nodeOrders, Map<String, String> labelOverrides) {
        StringBuilder builder = new StringBuilder(labelOverrides.getOrDefault(rootLabel, rootLabel))
            .append(System.lineSeparator());
        appendChildren(builder, root, "", nodeOrders.getOrDefault(rootLabel, List.of()), nodeOrders, labelOverrides);
        return builder.toString();
    }

    private static List<Entry> orderEntries(List<Entry> entries, List<String> order) {
        if (order.isEmpty()) {
            return entries;
        }
        List<Entry> reordered = new ArrayList<>(entries);
        reordered.sort(Comparator.comparingInt(entry -> {
            int index = order.indexOf(entry.label());
            return index < 0 ? order.size() : index;
        }));
        return reordered;
    }

    private static void appendChildren(StringBuilder builder, Object value, String prefix, List<String> order,
            Map<String, List<String>> nodeOrders, Map<String, String> labelOverrides) {
        List<Entry> entries = orderEntries(entriesOf(value), order);
        for (int i = 0; i < entries.size(); i++) {
            appendNode(builder, entries.get(i), prefix, i == entries.size() - 1, nodeOrders, labelOverrides);
        }
    }

    private static void appendNode(StringBuilder builder, Entry entry, String prefix, boolean last,
            Map<String, List<String>> nodeOrders, Map<String, String> labelOverrides) {
        String displayLabel = labelOverrides.getOrDefault(entry.label(), entry.label());
        builder.append(prefix).append(last ? CONNECTOR_LAST : CONNECTOR_BRANCH).append(displayLabel);
        Object value = entry.value();
        if (isBranch(value)) {
            builder.append(System.lineSeparator());
            appendChildren(builder, value, prefix + (last ? INDENT_LAST : INDENT_BRANCH),
                nodeOrders.getOrDefault(entry.label(), List.of()), nodeOrders, labelOverrides);
        } else {
            builder.append(" = ").append(formatLeaf(entry.label(), value)).append(System.lineSeparator());
        }
    }

    private static boolean isBranch(@Nullable Object value) {
        if (value instanceof Record) {
            return true;
        }
        return value instanceof Map<?, ?> map && !map.isEmpty();
    }

    private static List<Entry> entriesOf(Object value) {
        if (value instanceof Record record) {
            return recordEntries(record);
        }
        if (value instanceof Map<?, ?> map) {
            return mapEntries(map);
        }
        return List.of();
    }

    private static List<Entry> recordEntries(Record record) {
        RecordComponent[] components = record.getClass().getRecordComponents();
        List<Entry> entries = new ArrayList<>(components.length);
        for (RecordComponent component : components) {
            entries.add(new Entry(component.getName(), readComponent(record, component)));
        }
        return entries;
    }

    private static @Nullable Object readComponent(Record record, RecordComponent component) {
        try {
            return component.getAccessor().invoke(record);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot read config component " + component.getName(), e);
        }
    }

    private static List<Entry> mapEntries(Map<?, ?> map) {
        return map.entrySet().stream()
            .sorted(Comparator.comparing(e -> String.valueOf(e.getKey())))
            .map(e -> new Entry(String.valueOf(e.getKey()), e.getValue()))
            .toList();
    }

    private static String formatLeaf(String label, @Nullable Object value) {
        if (value == null) {
            return "(not set)";
        }
        if (value instanceof Map<?, ?>) {
            return "(none)";
        }
        if (isSecret(label)) {
            return maskSecret(value.toString());
        }
        if (value instanceof String s && s.isBlank()) {
            return "(empty)";
        }
        return value.toString();
    }

    private static boolean isSecret(String label) {
        String lower = label.toLowerCase(Locale.ROOT);
        return lower.contains("password") || lower.contains("token") || lower.contains("apikey");
    }

    private static String maskSecret(String rawValue) {
        return rawValue.isBlank() ? "(empty)" : "****";
    }

    private record Entry(String label, @Nullable Object value) {
    }
}
