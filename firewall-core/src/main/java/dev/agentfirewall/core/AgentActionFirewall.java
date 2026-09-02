/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Fail-closed orchestration around an authorization engine and sanitized trace sink. */
public final class AgentActionFirewall {
    private final AgentAuthorizationEngine authorizationEngine;
    private final AuthorizationTraceSink traceSink;
    private final Clock clock;

    public AgentActionFirewall(
            AgentAuthorizationEngine authorizationEngine,
            AuthorizationTraceSink traceSink,
            Clock clock) {
        this.authorizationEngine = Objects.requireNonNull(
                authorizationEngine, "authorizationEngine must not be null");
        this.traceSink = Objects.requireNonNull(traceSink, "traceSink must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public AuthorizationDecision authorize(AgentActionRequest request) {
        Objects.requireNonNull(request, "request must not be null");

        AuthorizationDecision decision;
        try {
            decision = Objects.requireNonNull(
                    authorizationEngine.authorize(request),
                    "authorization engine returned null");
        } catch (RuntimeException engineFailure) {
            decision = AuthorizationDecision.deny(
                    UUID.randomUUID().toString(),
                    AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE,
                    Instant.now(clock));
        }

        try {
            traceSink.record(AuthorizationTraceEvent.from(request, decision));
        } catch (RuntimeException ignored) {
            // Trace availability must not change the authorization outcome.
        }
        return decision;
    }
}
