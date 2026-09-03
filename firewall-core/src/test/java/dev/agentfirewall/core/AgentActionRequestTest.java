/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentActionRequestTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");

    @Test
    void buildsRequestFromCanonicalAction() {
        McpToolAction action = new McpToolAction(
                "inventory", "purchase", "{}".getBytes(StandardCharsets.UTF_8));
        ActionDigestService digests = new ActionDigestService();

        AgentActionRequest request = AgentActionRequest.fromAction(
                "request-1",
                action,
                NOW,
                Map.of(),
                new PresentedCredentials("aoat", "wit", null),
                digests);

        assertEquals(ActionProtocol.MCP, request.protocol());
        assertEquals("tools/call", request.operation());
        assertEquals("inventory/purchase", request.resource());
        assertEquals(digests.digest(action), request.requestDigest());
        assertEquals(action, request.action());
    }

    @Test
    void rejectsActionMetadataAndDigestMismatch() {
        var action = new McpToolAction("inventory", "purchase", new byte[0]);
        var credentials = new PresentedCredentials("aoat", "wit", null);
        assertThrows(IllegalArgumentException.class, () -> new AgentActionRequest(
                "id", ActionProtocol.MCP, "tools/call", action.resource(), "sha256:" + "a".repeat(64),
                NOW, Map.of(), credentials, action));
        assertThrows(IllegalArgumentException.class, () -> new AgentActionRequest(
                "id", ActionProtocol.HTTP, "POST", action.resource(), new ActionDigestService().digest(action),
                NOW, Map.of(), credentials, action));
    }

    @Test
    void rejectsNonCanonicalDigestEncoding() {
        assertThrows(IllegalArgumentException.class, () -> new AgentActionRequest(
                "request-1",
                ActionProtocol.MCP,
                "tools/call",
                "inventory/purchase",
                "sha256:ABC123",
                NOW,
                Map.of(),
                new PresentedCredentials("aoat", "wit", null)));
    }
}
