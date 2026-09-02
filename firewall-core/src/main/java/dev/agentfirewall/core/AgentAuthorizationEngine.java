/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

/**
 * Stable boundary between the firewall and a concrete authorization implementation.
 *
 * <p>The Open Agent Auth adapter will implement this interface. No upstream type is exposed here.</p>
 */
@FunctionalInterface
public interface AgentAuthorizationEngine {
    AuthorizationDecision authorize(AgentActionRequest request);
}

