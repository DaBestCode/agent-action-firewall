/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import dev.agentfirewall.core.AgentAuthorizationEngine;
import dev.agentfirewall.core.ReplayProtection;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Experimental, local-trust HTTP profile; no upstream or JOSE types escape this API. */
public final class HttpAuthorizationProfile {
    private HttpAuthorizationProfile() { }

    /** Exact issuer, audience and administrator-provisioned public key. No remote key discovery. */
    public record Trust(String issuer, String audience, RSAPublicKey key) {
        public Trust {
            label(issuer); label(audience); Objects.requireNonNull(key);
            if (key.getModulus().bitLength() < 2048) throw new IllegalArgumentException("RSA key too small");
        }
    }

    /** Administrator-owned human/workload binding and its permitted policy identifiers. */
    public record Binding(String humanSubject, String issuedTo, String workloadSubject,
                          Instant expiresAt, Set<String> policyIds) {
        public Binding {
            label(humanSubject); label(issuedTo); label(workloadSubject);
            Objects.requireNonNull(expiresAt);
            policyIds = Set.copyOf(policyIds);
            policyIds.forEach(HttpAuthorizationProfile::label);
        }
    }

    /** An exact action-digest allowlist, not a wildcard or scripting language. */
    public record Policy(Set<String> actionDigests) {
        public Policy {
            actionDigests = Set.copyOf(actionDigests);
            if (actionDigests.stream().anyMatch(d -> !d.matches("sha256:[0-9a-f]{64}"))) {
                throw new IllegalArgumentException("Invalid policy digest");
            }
        }
    }

    /** Creates a fail-closed engine. Keep one shared replay store for every instance serving an audience. */
    public static AgentAuthorizationEngine create(Trust authorizationTrust, Trust workloadTrust,
            Map<String, Binding> bindings, Map<String, Policy> policies, ReplayProtection replay, Clock clock) {
        Objects.requireNonNull(authorizationTrust); Objects.requireNonNull(workloadTrust);
        bindings = Map.copyOf(bindings); policies = Map.copyOf(policies);
        bindings.keySet().forEach(HttpAuthorizationProfile::label);
        policies.keySet().forEach(HttpAuthorizationProfile::label);
        return new SignedHttpEngine(authorizationTrust, workloadTrust, bindings, policies,
                Objects.requireNonNull(replay), Objects.requireNonNull(clock));
    }

    private static void label(String value) {
        if (value == null || value.isBlank() || value.length() > 256
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid profile label");
        }
    }
}
