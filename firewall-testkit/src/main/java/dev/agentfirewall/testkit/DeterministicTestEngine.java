/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.testkit;

import dev.agentfirewall.core.ActionDigestService;
import dev.agentfirewall.core.AgentActionRequest;
import dev.agentfirewall.core.AgentAuthorizationEngine;
import dev.agentfirewall.core.AuthorizationDecision;
import dev.agentfirewall.core.AuthorizationReason;
import dev.agentfirewall.core.McpToolAction;
import dev.agentfirewall.core.PresentedCredentials;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TEST ONLY: exact-match fake authorization, with no token parsing or signature verification.
 * Never place firewall-testkit on a production runtime classpath.
 */
public final class DeterministicTestEngine implements AgentAuthorizationEngine {
    private static final Instant NOW = Instant.parse("2026-09-02T12:00:00Z");
    private final AgentActionRequest approved;
    private final AtomicLong sequence = new AtomicLong();

    private DeterministicTestEngine(AgentActionRequest approved) {
        this.approved = approved;
    }

    public static AuthorizationEngineScenario scenario() {
        var credentials = new PresentedCredentials("test-only-aoat", "test-only-wit", "test-only-wpt");
        AgentActionRequest approved = request("allowed", "purchase", "{\"amount\":75}", credentials);
        return new AuthorizationEngineScenario(
                new DeterministicTestEngine(approved),
                approved,
                request("invalid", "purchase", "{\"amount\":75}",
                        new PresentedCredentials("invalid-test-aoat", "test-only-wit", "test-only-wpt")),
                request("denied", "refund", "{\"amount\":75}", credentials),
                request("altered", "purchase", "{\"amount\":76}", credentials));
    }

    @Override
    public AuthorizationDecision authorize(AgentActionRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        String id = "test-decision-" + sequence.incrementAndGet();
        PresentedCredentials actual = request.credentials();
        PresentedCredentials expected = approved.credentials();
        AuthorizationReason reason;
        if (!expected.agentOperationAuthorizationToken().equals(actual.agentOperationAuthorizationToken())
                || !expected.workloadIdentityToken().equals(actual.workloadIdentityToken())
                || !expected.workloadProofToken().equals(actual.workloadProofToken())) {
            reason = AuthorizationReason.AOAT_SIGNATURE_INVALID;
        } else if (request.protocol() != approved.protocol()
                || !request.operation().equals(approved.operation())
                || !request.resource().equals(approved.resource())
                || !request.attributes().equals(approved.attributes())) {
            reason = AuthorizationReason.POLICY_DENIED;
        } else if (!request.requestDigest().equals(approved.requestDigest())) {
            reason = AuthorizationReason.REQUEST_DIGEST_MISMATCH;
        } else {
            reason = AuthorizationReason.POLICY_MATCHED;
        }
        return new AuthorizationDecision(id, reason.outcome(), reason, NOW,
                reason == AuthorizationReason.POLICY_MATCHED ? List.of("test-policy") : List.of());
    }

    private static AgentActionRequest request(
            String id, String tool, String arguments, PresentedCredentials credentials) {
        return AgentActionRequest.fromAction(id,
                new McpToolAction("test-inventory", tool, arguments.getBytes(StandardCharsets.UTF_8)),
                NOW, Map.of(), credentials, new ActionDigestService());
    }
}
