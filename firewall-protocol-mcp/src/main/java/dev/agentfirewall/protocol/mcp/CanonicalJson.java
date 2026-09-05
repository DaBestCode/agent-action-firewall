/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import com.fasterxml.jackson.core.*;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;

/** Bounded safe-integer JSON subset. Deliberately not a full RFC 8785 implementation. */
final class CanonicalJson {
    private static final BigDecimal MAX = new BigDecimal("9007199254740991");
    private static final JsonFactory FACTORY = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32)
                    .maxStringLength(16384).maxNameLength(1024).maxNumberLength(128).build()).build();

    static Object parse(byte[] input) {
        if (input == null || input.length == 0 || input.length > 65536) throw invalid();
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(input)).toString();
            try (var parser = FACTORY.createParser(text)) {
                parser.nextToken();
                Object value = read(parser, new int[] {0});
                if (parser.nextToken() != null) throw invalid();
                return value;
            }
        } catch (Exception rejected) {
            // No cause: parser diagnostics can contain secrets from arguments.
            throw invalid();
        }
    }

    private static Object read(JsonParser parser, int[] count) throws Exception {
        if (++count[0] > 10000 || parser.currentToken() == null) throw invalid();
        return switch (parser.currentToken()) {
            case START_OBJECT -> {
                var map = new TreeMap<String, Object>();
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    if (parser.currentToken() != JsonToken.FIELD_NAME) throw invalid();
                    String key = validUnicode(parser.currentName());
                    parser.nextToken(); map.put(key, read(parser, count));
                }
                yield map;
            }
            case START_ARRAY -> {
                var list = new ArrayList<Object>();
                while (parser.nextToken() != JsonToken.END_ARRAY) list.add(read(parser, count));
                yield list;
            }
            case VALUE_STRING -> validUnicode(parser.getText());
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> {
                var value = new BigDecimal(parser.getText());
                if (Math.abs((long) value.scale()) > 1000 || value.abs().compareTo(MAX) > 0) throw invalid();
                yield value.toBigIntegerExact().longValueExact();
            }
            case VALUE_TRUE -> true;
            case VALUE_FALSE -> false;
            case VALUE_NULL -> null;
            default -> throw invalid();
        };
    }

    private static String validUnicode(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i == value.length() || !Character.isLowSurrogate(value.charAt(i))) throw invalid();
            } else if (Character.isLowSurrogate(c)) throw invalid();
        }
        return value;
    }

    static byte[] bytes(Object value) {
        var output = new StringBuilder(); append(value, output);
        byte[] encoded = output.toString().getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 65536) throw invalid();
        return encoded;
    }

    private static void append(Object value, StringBuilder output) {
        if (value instanceof Map<?, ?> map) {
            output.append('{'); boolean first = true;
            var sorted = new TreeMap<String, Object>();
            map.forEach((key, item) -> sorted.put((String) key, item));
            for (var entry : sorted.entrySet()) {
                if (!first) output.append(','); first = false;
                string(entry.getKey(), output); output.append(':'); append(entry.getValue(), output);
            }
            output.append('}');
        } else if (value instanceof List<?> list) {
            output.append('[');
            for (int i = 0; i < list.size(); i++) { if (i > 0) output.append(','); append(list.get(i), output); }
            output.append(']');
        } else if (value instanceof String text) string(text, output);
        else if (value == null) output.append("null");
        else if (value instanceof Long || value instanceof Boolean) output.append(value);
        else throw invalid();
    }

    private static void string(String value, StringBuilder output) {
        output.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (c < 0x20) {
                        output.append("\\u00").append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 15, 16));
                    } else output.append(c);
                }
            }
        }
        output.append('"');
    }

    static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid or unsupported MCP JSON"); }
}
