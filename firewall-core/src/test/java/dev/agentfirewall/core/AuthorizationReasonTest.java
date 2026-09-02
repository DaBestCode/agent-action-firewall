/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthorizationReasonTest {
    @Test
    void exposesControlledReasonCodeAndExplanation() {
        AuthorizationDecision decision = AuthorizationDecision.deny(
                "decision-1", AuthorizationReason.REPLAY_DETECTED, Instant.EPOCH);

        assertEquals("REPLAY_DETECTED", decision.reasonCode());
        assertEquals(AuthorizationReason.REPLAY_DETECTED.explanation(), decision.explanation());
    }

    @Test
    void rejectsReasonWhoseOutcomeDoesNotMatchDecision() {
        assertThrows(IllegalArgumentException.class, () -> new AuthorizationDecision(
                "decision-1",
                AuthorizationOutcome.ALLOW,
                AuthorizationReason.POLICY_DENIED,
                Instant.EPOCH,
                List.of()));
    }

    @Test
    void everyReasonHasControlledDisplayText() {
        for (AuthorizationReason reason : AuthorizationReason.values()) {
            assertEquals(reason.outcome() == AuthorizationOutcome.ALLOW,
                    reason == AuthorizationReason.POLICY_MATCHED);
            if (reason.explanation().isBlank()) {
                throw new AssertionError("blank explanation for " + reason);
            }
        }
    }
}
