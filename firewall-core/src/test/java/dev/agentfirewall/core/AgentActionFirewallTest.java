/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AgentActionFirewallTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String DIGEST = "sha256:" + "a".repeat(64);

    @Test
    void returnsEngineDecisionAndRecordsIt() {
        AgentActionRequest request = request();
        AuthorizationDecision allowed = new AuthorizationDecision(
                "decision-1",
                AuthorizationOutcome.ALLOW,
                AuthorizationReason.POLICY_MATCHED,
                NOW,
                List.of("policy-1"));
        AtomicReference<AuthorizationTraceEvent> traced = new AtomicReference<>();
        AgentActionFirewall firewall = new AgentActionFirewall(
                ignored -> allowed,
                traced::set,
                CLOCK);

        AuthorizationDecision actual = firewall.authorize(request);

        assertSame(allowed, actual);
        assertEquals(allowed.decisionId(), traced.get().decisionId());
        assertEquals(request.requestDigest(), traced.get().requestDigest());
    }

    @Test
    void failsClosedWhenEngineThrows() {
        AgentActionFirewall firewall = new AgentActionFirewall(
                ignored -> { throw new IllegalStateException("token contents must not escape"); },
                AuthorizationTraceSink.NOOP,
                CLOCK);

        AuthorizationDecision decision = firewall.authorize(request());

        assertFalse(decision.allowed());
        assertEquals("AUTHORIZATION_ENGINE_FAILURE", decision.reasonCode());
        assertEquals("Authorization could not be established.", decision.explanation());
        assertEquals(NOW, decision.decidedAt());
    }

    @Test
    void failsClosedWhenEngineReturnsNullAndRecordsFailure() {
        AtomicReference<AuthorizationTraceEvent> recorded = new AtomicReference<>();
        AgentActionFirewall firewall = new AgentActionFirewall(ignored -> null, recorded::set, CLOCK);
        AuthorizationDecision decision = firewall.authorize(request());
        assertFalse(decision.allowed());
        assertEquals(AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE, recorded.get().reason());
    }

    @Test
    void traceFailureDoesNotOverrideAuthorizationDecision() {
        AuthorizationDecision denied = AuthorizationDecision.deny(
                "decision-2", AuthorizationReason.SCOPE_EXCEEDED, NOW);
        AgentActionFirewall firewall = new AgentActionFirewall(
                ignored -> denied,
                ignored -> { throw new IllegalStateException("trace store unavailable"); },
                CLOCK);

        assertSame(denied, firewall.authorize(request()));
    }

    private AgentActionRequest request() {
        return new AgentActionRequest(
                "request-1",
                ActionProtocol.MCP,
                "tools/call",
                "inventory.purchase",
                DIGEST,
                NOW,
                Map.of("amount", "75"),
                new PresentedCredentials("aoat-token", "wit-token", "wpt-token"));
    }
}
