/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import dev.agentfirewall.core.ActionDigestService;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class McpCallCanonicalizerTest {
    private final McpCallCanonicalizer canonicalizer = new McpCallCanonicalizer();

    @Test void matchesIndependentActionV2GoldenVector() {
        var call = call("{\"sku\":\"A-1\",\"quantity\":2.0}");
        assertEquals("{\"quantity\":2,\"sku\":\"A-1\"}", text(call.action().canonicalArguments()));
        assertEquals("sha256:96aee381e7ed8f5222fe93c559b22bcb747c0b1902537caedc94c012d2f5cf7b", digest(call));
    }

    @Test void canonicalizesOrderingEscapesAndIntegralNumberSpellings() {
        var a = call("{\"z\":1.0,\"a\":{\"b\":true,\"a\":null},\"text\":\"\\u0061\\/\",\"n\":-0}");
        var b = call("{\"text\":\"a/\",\"n\":0e1,\"a\":{\"a\":null,\"b\":true},\"z\":1e0}");
        assertEquals("{\"a\":{\"a\":null,\"b\":true},\"n\":0,\"text\":\"a/\",\"z\":1}", text(a.action().canonicalArguments()));
        assertArrayEquals(a.forwardingBytes(), b.forwardingBytes());
        assertEquals(digest(a), digest(b));
        assertArrayEquals(a.forwardingBytes(), canonicalizer.canonicalize("inventory", a.forwardingBytes()).forwardingBytes());
    }

    @Test void preservesArrayOrderStringsAndUnicodeWithoutNormalization() {
        assertNotEquals(digest(call("{\"a\":[1,2]}")), digest(call("{\"a\":[2,1]}")));
        assertNotEquals(digest(call("{\"a\":1}")), digest(call("{\"a\":\"1\"}")));
        assertNotEquals(digest(call("{\"a\":\"é\"}")), digest(call("{\"a\":\"é\"}")));
        assertEquals("{\"😀\":1,\"\":2}", text(call("{\"\":2,\"😀\":1}").action().canonicalArguments()));
        assertEquals("{\"a\":\"\\b\\f\\n\\r\\t\\u0000\\\"\\\\/\"}",
                text(call("{\"a\":\"\\b\\f\\n\\r\\t\\u0000\\\"\\\\\\/\"}").action().canonicalArguments()));
    }

    @Test void bindsToolAndConfiguredServerButNotRpcCorrelationId() {
        var original = call("{}");
        byte[] otherId = text(original.forwardingBytes()).replace("\"id\":1", "\"id\":\"other\"").getBytes(StandardCharsets.UTF_8);
        assertEquals(digest(original), digest(canonicalizer.canonicalize("inventory", otherId)));
        assertNotEquals(digest(original), digest(canonicalizer.canonicalize("billing", original.forwardingBytes())));
        byte[] otherTool = text(original.forwardingBytes()).replace("\"buy\"", "\"delete\"").getBytes(StandardCharsets.UTF_8);
        assertNotEquals(digest(original), digest(canonicalizer.canonicalize("inventory", otherTool)));
    }

    @Test void missingArgumentsBecomeEmptyObjectAndReturnedBytesAreDefensive() {
        var missing = canonicalizer.canonicalize("inventory", bytes("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"buy\"}}"));
        assertArrayEquals(call("{}").forwardingBytes(), missing.forwardingBytes());
        byte[] forwarded = missing.forwardingBytes(); forwarded[0] = 'x';
        byte[] arguments = missing.action().canonicalArguments(); arguments[0] = 'x';
        assertEquals('{', missing.forwardingBytes()[0]); assertEquals("{}", text(missing.action().canonicalArguments()));
        assertEquals("CanonicalToolCall[redacted]", call("{\"secret\":\"private\"}").toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "{\"x\":{\"a\":1,\"a\":2}}",
            "{\"x\":0.1}", "{\"x\":9007199254740992}", "{\"x\":-9007199254740992}", "{\"x\":1e999999999}",
            "{\"x\":1e-999999999}", "{\"x\":NaN}", "{\"x\":Infinity}", "{\"x\":01}", "{\"x\":+1}",
            "{\"x\":\"\\ud800\"}", "{\"x\":\"\\udc00\"}", "{\"\\ud800\":1}", "{\"x\":1,}", "{/* secret */}",
            "[]", "null", "1", "\"string\""})
    void rejectsAmbiguousOrUnsupportedArguments(String arguments) {
        var exception = assertThrows(IllegalArgumentException.class, () -> call(arguments));
        assertEquals("Invalid or unsupported MCP JSON", exception.getMessage()); assertNull(exception.getCause());
    }

    @ParameterizedTest
    @ValueSource(strings = {"[]", "{}", "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"buy\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"tools/call\",\"params\":{\"name\":\"buy\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"name\":\"buy\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"buy\",\"_meta\":{}}}"})
    void rejectsUnsupportedEnvelopes(String envelope) {
        assertThrows(IllegalArgumentException.class, () -> canonicalizer.canonicalize("inventory", bytes(envelope)));
    }

    @Test void rejectsInvalidUtf8TrailingDocumentsAndResourceExhaustion() {
        assertThrows(IllegalArgumentException.class, () -> canonicalizer.canonicalize("inventory", new byte[] {(byte) 0xc3, 0x28}));
        assertThrows(IllegalArgumentException.class, () -> canonicalizer.canonicalize("inventory", new byte[65537]));
        assertThrows(IllegalArgumentException.class, () -> canonicalizer.canonicalize("inventory", bytes(text(call("{}").forwardingBytes()) + "{}")));
        assertThrows(IllegalArgumentException.class, () -> call("{\"x\":".repeat(33) + "0" + "}".repeat(33)));
        assertThrows(IllegalArgumentException.class, () -> call("{\"x\":\"" + "a".repeat(16385) + "\"}"));
        assertThrows(IllegalArgumentException.class, () -> call("{\"x\":[" + "0,".repeat(9999) + "0]}"));
        assertThrows(IllegalArgumentException.class, () -> call("{\"x\":[" + "1e15,".repeat(5000) + "0]}"));
        assertThrows(IllegalArgumentException.class, () -> canonicalizer.canonicalize("https://model-chosen", call("{}").forwardingBytes()));
    }

    @Test void acceptsSafeIntegerEdgesAndIsThreadSafe() throws Exception {
        var expected = call("{\"min\":-9007199254740991,\"max\":9007199254740991}");
        var executor = Executors.newFixedThreadPool(4);
        try {
            List<Callable<byte[]>> tasks = new ArrayList<>();
            for (int i = 0; i < 40; i++) tasks.add(() -> canonicalizer.canonicalize("inventory", expected.forwardingBytes()).forwardingBytes());
            for (var result : executor.invokeAll(tasks)) assertArrayEquals(expected.forwardingBytes(), result.get());
        } finally { executor.shutdownNow(); }
    }

    private CanonicalToolCall call(String arguments) {
        return canonicalizer.canonicalize("inventory", bytes("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"buy\",\"arguments\":" + arguments + "}}"));
    }
    private static String digest(CanonicalToolCall call) { return new ActionDigestService().digest(call.action()); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] value) { return new String(value, StandardCharsets.UTF_8); }
}
