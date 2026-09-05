/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

/** Trusted routing boundary. Credentials are intentionally absent from this interface. */
@FunctionalInterface
public interface McpForwarder {
    byte[] forward(String serverId, byte[] canonicalRequest) throws Exception;
}
