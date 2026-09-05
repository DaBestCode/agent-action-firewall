/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import dev.agentfirewall.core.McpToolAction;

/** Immutable pair: the action to authorize and the exact canonical request to forward afterward. */
public final class CanonicalToolCall {
    private final McpToolAction action;
    private final byte[] forwardingBytes;
    private final byte[] correlationId;
    CanonicalToolCall(McpToolAction action, byte[] forwardingBytes, byte[] correlationId) {
        this.action = action; this.forwardingBytes = forwardingBytes.clone(); this.correlationId = correlationId.clone();
    }
    public McpToolAction action() { return action; }
    public byte[] forwardingBytes() { return forwardingBytes.clone(); }
    byte[] correlationId() { return correlationId.clone(); }
    @Override public String toString() { return "CanonicalToolCall[redacted]"; }
}
