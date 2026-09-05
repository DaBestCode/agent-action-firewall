/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import dev.agentfirewall.core.McpToolAction;

/** Immutable pair: the action to authorize and the exact canonical request to forward afterward. */
public final class CanonicalToolCall {
    private final McpToolAction action;
    private final byte[] forwardingBytes;
    CanonicalToolCall(McpToolAction action, byte[] forwardingBytes) {
        this.action = action; this.forwardingBytes = forwardingBytes.clone();
    }
    public McpToolAction action() { return action; }
    public byte[] forwardingBytes() { return forwardingBytes.clone(); }
    @Override public String toString() { return "CanonicalToolCall[redacted]"; }
}
