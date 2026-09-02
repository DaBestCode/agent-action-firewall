/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Auditable, token-free result returned by an authorization engine. */
public record AuthorizationDecision(
        String decisionId,
        AuthorizationOutcome outcome,
        String reasonCode,
        String explanation,
        Instant decidedAt,
        List<String> policyIds) {

    public AuthorizationDecision {
        decisionId = requireText(decisionId, "decisionId");
        outcome = Objects.requireNonNull(outcome, "outcome must not be null");
        reasonCode = requireText(reasonCode, "reasonCode");
        explanation = requireText(explanation, "explanation");
        decidedAt = Objects.requireNonNull(decidedAt, "decidedAt must not be null");
        policyIds = List.copyOf(Objects.requireNonNull(policyIds, "policyIds must not be null"));
    }

    public boolean allowed() {
        return outcome == AuthorizationOutcome.ALLOW;
    }

    public static AuthorizationDecision deny(
            String decisionId, String reasonCode, String explanation, Instant decidedAt) {
        return new AuthorizationDecision(
                decisionId,
                AuthorizationOutcome.DENY,
                reasonCode,
                explanation,
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

