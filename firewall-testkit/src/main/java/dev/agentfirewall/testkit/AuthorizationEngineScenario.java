/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.testkit;

import dev.agentfirewall.core.AgentActionRequest;
import dev.agentfirewall.core.AgentAuthorizationEngine;
import java.util.Objects;

/** An adapter supplies fresh engine state and real signed fixtures for each contract test. */
public record AuthorizationEngineScenario(
        AgentAuthorizationEngine engine,
        AgentActionRequest allowed,
        AgentActionRequest invalidCredentials,
        AgentActionRequest deniedAction,
        AgentActionRequest alteredPayload) {
    public AuthorizationEngineScenario {
        Objects.requireNonNull(engine, "engine");
        Objects.requireNonNull(allowed, "allowed");
        Objects.requireNonNull(invalidCredentials, "invalidCredentials");
        Objects.requireNonNull(deniedAction, "deniedAction");
        Objects.requireNonNull(alteredPayload, "alteredPayload");
    }
}
