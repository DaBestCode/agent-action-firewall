/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.testkit;

import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.agentfirewall.core.AuthorizationDecision;
import dev.agentfirewall.core.AuthorizationOutcome;
import dev.agentfirewall.core.AuthorizationReason;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Demonstrates that the contract detects both always-allow and always-deny broken engines. */
class AuthorizationEngineContractSensitivityTest {
    @Test
    void rejectsAlwaysAllowEngineOnAllNegativeFixtures() {
        var contract = contractReturning(new AuthorizationDecision(
                "bad-allow", AuthorizationOutcome.ALLOW, AuthorizationReason.POLICY_MATCHED,
                Instant.EPOCH, List.of()));
        assertThrows(AssertionError.class, contract::deniesInvalidCredentials);
        assertThrows(AssertionError.class, contract::deniesUnauthorizedAction);
        assertThrows(AssertionError.class, contract::deniesChangedPayloadBinding);
    }

    @Test
    void rejectsAlwaysDenyEngineOnPositiveFixture() {
        var contract = contractReturning(AuthorizationDecision.deny(
                "bad-deny", AuthorizationReason.POLICY_DENIED, Instant.EPOCH));
        assertThrows(AssertionError.class, contract::allowsAuthorizedAction);
    }

    private AuthorizationEngineContract contractReturning(AuthorizationDecision decision) {
        return () -> {
            var fixture = DeterministicTestEngine.scenario();
            return new AuthorizationEngineScenario(ignored -> decision, fixture.allowed(),
                    fixture.invalidCredentials(), fixture.deniedAction(), fixture.alteredPayload());
        };
    }
}
