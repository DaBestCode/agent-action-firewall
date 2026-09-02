/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.agentfirewall.core.AgentActionFirewall;
import dev.agentfirewall.core.AuthorizationDecision;
import dev.agentfirewall.core.InMemoryAuthorizationTraceRepository;
import dev.agentfirewall.core.TraceQuery;
import java.time.Clock;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Reusable JUnit contract for authorization adapters. Implement scenario() with fresh state.
 * This tests the firewall-facing contract, not cryptographic protocol correctness.
 */
public interface AuthorizationEngineContract {
    AuthorizationEngineScenario scenario();

    @Test
    default void allowsAuthorizedAction() {
        var fixture = scenario();
        AuthorizationDecision decision = fixture.engine().authorize(fixture.allowed());
        assertNotNull(decision);
        assertTrue(decision.allowed());
        assertEquals(decision.outcome(), decision.reason().outcome());
    }

    @Test
    default void deniesInvalidCredentials() {
        var fixture = scenario();
        AuthorizationDecision decision = fixture.engine().authorize(fixture.invalidCredentials());
        assertNotNull(decision);
        assertFalse(decision.allowed());
    }

    @Test
    default void deniesUnauthorizedAction() {
        var fixture = scenario();
        AuthorizationDecision decision = fixture.engine().authorize(fixture.deniedAction());
        assertNotNull(decision);
        assertFalse(decision.allowed());
    }

    @Test
    default void deniesChangedPayloadBinding() {
        var fixture = scenario();
        AuthorizationDecision decision = fixture.engine().authorize(fixture.alteredPayload());
        assertNotNull(decision);
        assertFalse(decision.allowed());
    }

    @Test
    default void recordsAllowedDecisionThroughFirewall() {
        var fixture = scenario();
        var store = new InMemoryAuthorizationTraceRepository(10, Duration.ofMinutes(1), Clock.systemUTC());
        var firewall = new AgentActionFirewall(fixture.engine(), store, Clock.systemUTC());
        var decision = firewall.authorize(fixture.allowed());
        var traces = store.find(TraceQuery.latest(10));
        assertTrue(decision.allowed());
        assertEquals(1, traces.size());
        assertEquals(decision.decisionId(), traces.get(0).event().decisionId());
        assertEquals(fixture.allowed().requestDigest(), traces.get(0).event().requestDigest());
    }

    @Test
    default void recordsDenialThroughFirewall() {
        var fixture = scenario();
        var store = new InMemoryAuthorizationTraceRepository(10, Duration.ofMinutes(1), Clock.systemUTC());
        var firewall = new AgentActionFirewall(fixture.engine(), store, Clock.systemUTC());
        var decision = firewall.authorize(fixture.invalidCredentials());
        var traces = store.find(TraceQuery.latest(10));
        assertFalse(decision.allowed());
        assertEquals(1, traces.size());
        assertEquals(decision.reason(), traces.get(0).event().reason());
    }
}
