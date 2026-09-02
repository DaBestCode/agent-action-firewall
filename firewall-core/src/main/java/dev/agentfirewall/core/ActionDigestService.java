/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/** Produces versioned SHA-256 bindings for canonical agent actions. */
public final class ActionDigestService {
    private static final String DOMAIN = "agent-action-firewall:action:v1";

    public String digest(CanonicalAction action) {
        Objects.requireNonNull(action, "action must not be null");
        MessageDigest digest = sha256();
        addText(digest, DOMAIN);
        addText(digest, action.protocol().name());

        if (action instanceof HttpAction http) {
            addText(digest, http.operation());
            addText(digest, http.target());
            addText(digest, http.mediaType());
            addBytes(digest, http.body());
        } else if (action instanceof McpToolAction mcp) {
            addText(digest, mcp.operation());
            addText(digest, mcp.serverId());
            addText(digest, mcp.toolName());
            addBytes(digest, mcp.canonicalArguments());
        } else {
            throw new IllegalArgumentException("unsupported canonical action type");
        }

        return "sha256:" + HexFormat.of().formatHex(digest.digest());
    }

    private static void addText(MessageDigest digest, String value) {
        addBytes(digest, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void addBytes(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
