/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Credential-free event safe to hand to a trace adapter.
 *
 * <p>Request attributes are intentionally excluded until a schema with explicit field-level
 * classification and redaction exists.</p>
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
        String reasonCode,
        Instant decidedAt,
        List<String> policyIds) {

    public AuthorizationTraceEvent {
        requestId = Objects.requireNonNull(requestId, "requestId must not be null");
        protocol = Objects.requireNonNull(protocol, "protocol must not be null");
        operation = Objects.requireNonNull(operation, "operation must not be null");
        resource = Objects.requireNonNull(resource, "resource must not be null");
        requestDigest = Objects.requireNonNull(requestDigest, "requestDigest must not be null");
        requestedAt = Objects.requireNonNull(requestedAt, "requestedAt must not be null");
        decisionId = Objects.requireNonNull(decisionId, "decisionId must not be null");
        outcome = Objects.requireNonNull(outcome, "outcome must not be null");
        reasonCode = Objects.requireNonNull(reasonCode, "reasonCode must not be null");
        decidedAt = Objects.requireNonNull(decidedAt, "decidedAt must not be null");
        policyIds = List.copyOf(Objects.requireNonNull(policyIds, "policyIds must not be null"));
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
                decision.reasonCode(),
                decision.decidedAt(),
                decision.policyIds());
    }
}
