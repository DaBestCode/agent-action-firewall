/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Framework-neutral description of the action being authorized. */
public record AgentActionRequest(
        String requestId,
        ActionProtocol protocol,
        String operation,
        String resource,
        String requestDigest,
        Instant requestedAt,
        Map<String, String> attributes,
        PresentedCredentials credentials,
        CanonicalAction action) {

    private static final Pattern SHA_256 = Pattern.compile("sha256:[0-9a-f]{64}");

    public AgentActionRequest {
        requestId = requireText(requestId, "requestId");
        protocol = Objects.requireNonNull(protocol, "protocol must not be null");
        operation = requireText(operation, "operation");
        resource = requireText(resource, "resource");
        requestDigest = requireDigest(requestDigest);
        requestedAt = Objects.requireNonNull(requestedAt, "requestedAt must not be null");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes must not be null"));
        credentials = Objects.requireNonNull(credentials, "credentials must not be null");
        if (action != null && (protocol != action.protocol()
                || !operation.equals(action.operation()) || !resource.equals(action.resource())
                || !requestDigest.equals(new ActionDigestService().digest(action)))) {
            throw new IllegalArgumentException("action must match request metadata and digest");
        }
    }

    /** Legacy metadata-only request. Real adapters may reject it when raw action binding is needed. */
    public AgentActionRequest(String requestId, ActionProtocol protocol, String operation,
            String resource, String requestDigest, Instant requestedAt,
            Map<String, String> attributes, PresentedCredentials credentials) {
        this(requestId, protocol, operation, resource, requestDigest, requestedAt, attributes, credentials, null);
    }

    public static AgentActionRequest fromAction(
            String requestId,
            CanonicalAction action,
            Instant requestedAt,
            Map<String, String> attributes,
            PresentedCredentials credentials,
            ActionDigestService digestService) {
        Objects.requireNonNull(action, "action must not be null");
        Objects.requireNonNull(digestService, "digestService must not be null");
        return new AgentActionRequest(
                requestId,
                action.protocol(),
                action.operation(),
                action.resource(),
                digestService.digest(action),
                requestedAt,
                attributes,
                credentials,
                action);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    private static String requireDigest(String value) {
        Objects.requireNonNull(value, "requestDigest must not be null");
        if (!SHA_256.matcher(value).matches()) {
            throw new IllegalArgumentException("requestDigest must be a lowercase SHA-256 digest");
        }
        return value;
    }
}
