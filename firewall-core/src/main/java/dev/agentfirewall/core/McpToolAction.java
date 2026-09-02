/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.util.Arrays;
import java.util.Objects;

/** Canonical security-relevant representation of an MCP {@code tools/call} request. */
public final class McpToolAction implements CanonicalAction {
    private final String serverId;
    private final String toolName;
    private final byte[] canonicalArguments;

    public McpToolAction(String serverId, String toolName, byte[] canonicalArguments) {
        this.serverId = requireText(serverId, "serverId");
        this.toolName = requireText(toolName, "toolName");
        this.canonicalArguments = Arrays.copyOf(
                Objects.requireNonNull(
                        canonicalArguments, "canonicalArguments must not be null"),
                canonicalArguments.length);
    }

    @Override
    public ActionProtocol protocol() {
        return ActionProtocol.MCP;
    }

    @Override
    public String operation() {
        return "tools/call";
    }

    @Override
    public String resource() {
        return serverId + "/" + toolName;
    }

    public String serverId() {
        return serverId;
    }

    public String toolName() {
        return toolName;
    }

    public byte[] canonicalArguments() {
        return Arrays.copyOf(canonicalArguments, canonicalArguments.length);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
