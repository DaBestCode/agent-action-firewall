/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import dev.agentfirewall.core.McpToolAction;
import java.util.Map;
import java.util.Set;

/** Strict tools/call extraction and aaf-mcp-json-v1 canonicalization, with no authorization side effects. */
public final class McpCallCanonicalizer {
    public static final String PROFILE = "aaf-mcp-json-v1";

    /** serverId comes from trusted routing configuration, never a model-supplied target URL. */
    public CanonicalToolCall canonicalize(String serverId, byte[] request) {
        if (serverId == null || !serverId.matches("[A-Za-z0-9_.-]{1,128}")) throw CanonicalJson.invalid();
        Object parsed = CanonicalJson.parse(request);
        if (!(parsed instanceof Map<?, ?> root) || !root.keySet().equals(Set.of("jsonrpc", "id", "method", "params"))
                || !"2.0".equals(root.get("jsonrpc")) || !"tools/call".equals(root.get("method"))) throw CanonicalJson.invalid();
        Object id = root.get("id");
        if (!(id instanceof Long) && !(id instanceof String text && !text.isBlank() && text.length() <= 256)) throw CanonicalJson.invalid();
        if (!(root.get("params") instanceof Map<?, ?> params)
                || !Set.of("name", "arguments").containsAll(params.keySet())
                || !(params.get("name") instanceof String name) || !name.matches("[A-Za-z0-9_.-]{1,128}")) throw CanonicalJson.invalid();
        Object arguments = params.containsKey("arguments") ? params.get("arguments") : Map.of();
        if (!(arguments instanceof Map<?, ?>)) throw CanonicalJson.invalid();
        var action = new McpToolAction(serverId, name, CanonicalJson.bytes(arguments));
        byte[] forward = CanonicalJson.bytes(Map.of("jsonrpc", "2.0", "id", id, "method", "tools/call",
                "params", Map.of("name", name, "arguments", arguments)));
        return new CanonicalToolCall(action, forward);
    }
}
