/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class McpToolActionTest {
    @Test
    void representsToolCallAndProtectsArgumentsFromMutation() {
        byte[] arguments = "{\"amount\":75}".getBytes(StandardCharsets.UTF_8);
        McpToolAction action = new McpToolAction("inventory", "purchase", arguments);
        arguments[0] = 0;
        byte[] returned = action.canonicalArguments();
        returned[1] = 0;

        assertEquals(ActionProtocol.MCP, action.protocol());
        assertEquals("tools/call", action.operation());
        assertEquals("inventory/purchase", action.resource());
        assertArrayEquals(
                "{\"amount\":75}".getBytes(StandardCharsets.UTF_8),
                action.canonicalArguments());
    }

    @Test
    void rejectsBlankIdentifiers() {
        assertThrows(IllegalArgumentException.class,
                () -> new McpToolAction(" ", "purchase", new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> new McpToolAction("inventory", " ", new byte[0]));
    }
}
