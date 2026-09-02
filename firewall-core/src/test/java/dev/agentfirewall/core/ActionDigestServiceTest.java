/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ActionDigestServiceTest {
    private final ActionDigestService digests = new ActionDigestService();

    @Test
    void producesStableVersionedDigest() {
        HttpAction action = new HttpAction(
                "post",
                URI.create("https://EXAMPLE.com:443/a/../purchases"),
                "application/json",
                "{\"amount\":75}".getBytes(StandardCharsets.UTF_8));

        assertEquals(
                "sha256:59265c78238835d78657537b15fd01cbf8bf7fbecfceebc52e78535849e1c145",
                digests.digest(action));
    }

    @Test
    void bindsEveryMcpFieldAndPayload() {
        String original = digests.digest(new McpToolAction("inventory", "purchase", bytes("{\"amount\":75}")));

        assertNotEquals(original,
                digests.digest(new McpToolAction("other-inventory", "purchase", bytes("{\"amount\":75}"))));
        assertNotEquals(original,
                digests.digest(new McpToolAction("inventory", "refund", bytes("{\"amount\":75}"))));
        assertNotEquals(original,
                digests.digest(new McpToolAction("inventory", "purchase", bytes("{\"amount\":76}"))));
    }

    @Test
    void bindsHttpQueryEvenThoughQueryIsExcludedFromTraceResource() {
        HttpAction first = new HttpAction(
                "GET", URI.create("https://example.com/items?page=1"), null, new byte[0]);
        HttpAction second = new HttpAction(
                "GET", URI.create("https://example.com/items?page=2"), null, new byte[0]);

        assertEquals(first.resource(), second.resource());
        assertNotEquals(digests.digest(first), digests.digest(second));
    }

    @Test
    void lengthPrefixPreventsFieldBoundaryAmbiguity() {
        String first = digests.digest(new McpToolAction("ab", "c", new byte[0]));
        String second = digests.digest(new McpToolAction("a", "bc", new byte[0]));

        assertNotEquals(first, second);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
