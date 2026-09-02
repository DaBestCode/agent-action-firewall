/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Auditable, token-free result returned by an authorization engine. */
public record AuthorizationDecision(
        String decisionId,
        AuthorizationOutcome outcome,
        AuthorizationReason reason,
        Instant decidedAt,
        List<String> policyIds) {

    public AuthorizationDecision {
        decisionId = requireText(decisionId, "decisionId");
        outcome = Objects.requireNonNull(outcome, "outcome must not be null");
        reason = Objects.requireNonNull(reason, "reason must not be null");
        if (reason.outcome() != outcome) {
            throw new IllegalArgumentException("reason outcome does not match decision outcome");
        }
        decidedAt = Objects.requireNonNull(decidedAt, "decidedAt must not be null");
        policyIds = List.copyOf(Objects.requireNonNull(policyIds, "policyIds must not be null"));
    }

    public boolean allowed() {
        return outcome == AuthorizationOutcome.ALLOW;
    }

    public String reasonCode() {
        return reason.name();
    }

    public String explanation() {
        return reason.explanation();
    }

    public static AuthorizationDecision deny(
            String decisionId, AuthorizationReason reason, Instant decidedAt) {
        return new AuthorizationDecision(
                decisionId,
                AuthorizationOutcome.DENY,
                reason,
                decidedAt,
                List.of());
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
