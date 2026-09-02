/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthorizationTraceEventTest {
    private static final String DIGEST = "sha256:" + "a".repeat(64);

    @Test
    void traceSchemaCannotCarryCredentialsOrRequestAttributes() {
        AgentActionRequest request = new AgentActionRequest(
                "request-1",
                ActionProtocol.HTTP,
                "POST",
                "/purchases",
                DIGEST,
                Instant.parse("2026-09-01T12:00:00Z"),
                Map.of("sensitive-customer-reference", "customer-123"),
                new PresentedCredentials("secret-aoat", "secret-wit", "secret-wpt"));
        AuthorizationDecision decision = new AuthorizationDecision(
                "decision-1",
                AuthorizationOutcome.DENY,
                AuthorizationReason.SCOPE_EXCEEDED,
                Instant.parse("2026-09-01T12:00:01Z"),
                List.of("policy-1"));

        AuthorizationTraceEvent event = AuthorizationTraceEvent.from(request, decision);

        String rendered = event.toString();
        assertFalse(rendered.contains("secret-aoat"));
        assertFalse(rendered.contains("secret-wit"));
        assertFalse(rendered.contains("secret-wpt"));
        assertFalse(rendered.contains("customer-123"));

        for (RecordComponent component : AuthorizationTraceEvent.class.getRecordComponents()) {
            assertFalse(component.getType().equals(PresentedCredentials.class));
            assertFalse(component.getName().equals("attributes"));
            assertFalse(component.getName().equals("explanation"));
        }
    }
}
