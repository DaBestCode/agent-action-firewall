/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import dev.agentfirewall.core.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Canonicalize, authorize once, and forward only the authorized representation. */
public final class McpAuthorizationProxy {
    private static final int MAX_RESPONSE_BYTES = 1048576;
    private final McpCallCanonicalizer canonicalizer;
    private final AgentActionFirewall firewall;
    private final McpForwarder forwarder;
    private final Clock clock;

    public McpAuthorizationProxy(McpCallCanonicalizer canonicalizer, AgentActionFirewall firewall,
            McpForwarder forwarder, Clock clock) {
        this.canonicalizer = Objects.requireNonNull(canonicalizer);
        this.firewall = Objects.requireNonNull(firewall);
        this.forwarder = Objects.requireNonNull(forwarder);
        this.clock = Objects.requireNonNull(clock);
    }

    public McpProxyResult handle(String serverId, byte[] envelope, PresentedCredentials credentials) {
        Objects.requireNonNull(credentials, "credentials must not be null");
        final CanonicalToolCall call;
        try {
            call = canonicalizer.canonicalize(serverId, envelope);
        } catch (RuntimeException invalid) {
            return result(McpProxyResult.Status.MALFORMED, "null", -32600, "invalid_request", null);
        }
        var request = AgentActionRequest.fromAction(UUID.randomUUID().toString(), call.action(), clock.instant(),
                Map.of(), credentials, new ActionDigestService());
        AuthorizationDecision decision = firewall.authorize(request);
        if (!decision.allowed()) {
            return result(McpProxyResult.Status.REJECTED, text(call.correlationId()), -32001,
                    "authorization_denied", decision.decisionId());
        }
        try {
            byte[] response = forwarder.forward(serverId, call.forwardingBytes());
            if (response == null || response.length == 0 || response.length > MAX_RESPONSE_BYTES) {
                throw new IllegalStateException("invalid downstream response");
            }
            return new McpProxyResult(McpProxyResult.Status.FORWARDED, response, decision.decisionId());
        } catch (Exception failure) {
            return result(McpProxyResult.Status.DOWNSTREAM_FAILURE, text(call.correlationId()), -32002,
                    "downstream_unavailable", decision.decisionId());
        }
    }

    private static McpProxyResult result(McpProxyResult.Status status, String id, int code, String message,
            String decisionId) {
        String json = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":" + code
                + ",\"message\":\"" + message + "\"}}";
        return new McpProxyResult(status, json.getBytes(StandardCharsets.UTF_8), decisionId);
    }

    private static String text(byte[] value) { return new String(value, StandardCharsets.UTF_8); }
}
