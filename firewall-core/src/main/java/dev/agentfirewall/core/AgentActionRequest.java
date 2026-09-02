/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/** Framework-neutral description of the action being authorized. */
public record AgentActionRequest(
        String requestId,
        ActionProtocol protocol,
        String operation,
        String resource,
        String requestDigest,
        Instant requestedAt,
        Map<String, String> attributes,
        PresentedCredentials credentials) {

    public AgentActionRequest {
        requestId = requireText(requestId, "requestId");
        protocol = Objects.requireNonNull(protocol, "protocol must not be null");
        operation = requireText(operation, "operation");
        resource = requireText(resource, "resource");
        requestDigest = requireText(requestDigest, "requestDigest");
        requestedAt = Objects.requireNonNull(requestedAt, "requestedAt must not be null");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes must not be null"));
        credentials = Objects.requireNonNull(credentials, "credentials must not be null");
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}

