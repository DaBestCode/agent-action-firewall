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
                "sha256:571d7e5b19ba9ea5603ee7b83e476369616c3a22cb18855a896320b9b27f7c04",
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
    void doesNotCollapseMethodCaseOrRawPathVariants() {
        HttpAction original = new HttpAction("GET", URI.create("https://example.com/a/b"), null, new byte[0]);
        assertNotEquals(digests.digest(original), digests.digest(new HttpAction(
                "get", URI.create("https://example.com/a/b"), null, new byte[0])));
        for (String path : new String[] {"/a//b", "/a/./b", "/a/c/../b", "/a/%62"}) {
            assertNotEquals(digests.digest(original), digests.digest(new HttpAction(
                    "GET", URI.create("https://example.com" + path), null, new byte[0])));
        }
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
