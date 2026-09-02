/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.net.URI;
import java.util.List;
import java.util.Objects;

/**
 * Data-minimized event for trace adapters; identifiers must be non-sensitive correlation labels.
 *
 * <p>Request attributes are intentionally excluded until a schema with explicit field-level
 * classification and redaction exists. HTTP query/fragment data is removed at this boundary too.
 * Bounded strings are not a general-purpose secret detector: resource paths and IDs still need
 * trusted transport-side classification.</p>
 */
public record AuthorizationTraceEvent(
        String requestId,
        ActionProtocol protocol,
        String operation,
        String resource,
        String requestDigest,
        Instant requestedAt,
        String decisionId,
        AuthorizationOutcome outcome,
        AuthorizationReason reason,
        Instant decidedAt,
        List<String> policyIds) {

    public AuthorizationTraceEvent {
        requestId = requireLabel(requestId, "requestId", 256);
        protocol = Objects.requireNonNull(protocol, "protocol must not be null");
        operation = requireLabel(operation, "operation", 64);
        resource = Objects.requireNonNull(resource, "resource must not be null");
        if (protocol == ActionProtocol.HTTP) {
            resource = httpResource(resource);
        }
        resource = requireLabel(resource, "resource", 2048);
        requestDigest = Objects.requireNonNull(requestDigest, "requestDigest must not be null");
        if (!requestDigest.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("requestDigest must be a lowercase SHA-256 digest");
        }
        requestedAt = Objects.requireNonNull(requestedAt, "requestedAt must not be null");
        decisionId = requireLabel(decisionId, "decisionId", 256);
        outcome = Objects.requireNonNull(outcome, "outcome must not be null");
        reason = Objects.requireNonNull(reason, "reason must not be null");
        if (reason.outcome() != outcome) {
            throw new IllegalArgumentException("reason outcome does not match trace outcome");
        }
        decidedAt = Objects.requireNonNull(decidedAt, "decidedAt must not be null");
        policyIds = List.copyOf(Objects.requireNonNull(policyIds, "policyIds must not be null"));
        if (policyIds.size() > 32) {
            throw new IllegalArgumentException("policyIds must contain at most 32 labels");
        }
        policyIds.forEach(id -> requireLabel(id, "policyId", 256));
    }

    public static AuthorizationTraceEvent from(
            AgentActionRequest request, AuthorizationDecision decision) {
        Objects.requireNonNull(request, "request must not be null");
        Objects.requireNonNull(decision, "decision must not be null");
        return new AuthorizationTraceEvent(
                request.requestId(),
                request.protocol(),
                request.operation(),
                request.resource(),
                request.requestDigest(),
                request.requestedAt(),
                decision.decisionId(),
                decision.outcome(),
                decision.reason(),
                decision.decidedAt(),
                decision.policyIds());
    }

    public String reasonCode() {
        return reason.name();
    }

    private static String requireLabel(String value, String name, int maxLength) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank() || value.length() > maxLength || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " must be a bounded, nonblank label without controls");
        }
        return value;
    }

    private static String httpResource(String value) {
        try {
            URI uri = URI.create(value);
            if (uri.getRawUserInfo() != null) {
                throw new IllegalArgumentException("user-info is not allowed");
            }
        } catch (IllegalArgumentException invalid) {
            // Do not attach the parsing exception: it can include raw URI credentials.
            throw new IllegalArgumentException("HTTP trace resource must be a URI without user-info");
        }
        return value.split("[?#]", 2)[0];
    }
}
