/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;

/** Optional exact-match filters and a half-open decision-time interval. Null means no filter. */
public record TraceQuery(
        String requestId,
        ActionProtocol protocol,
        AuthorizationOutcome outcome,
        AuthorizationReason reason,
        Instant fromInclusive,
        Instant untilExclusive,
        int limit) {
    public static final int MAX_LIMIT = 1000;

    public TraceQuery {
        if (requestId != null && requestId.isBlank()) {
            throw new IllegalArgumentException("requestId filter must not be blank");
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new IllegalArgumentException("limit must be between 1 and 1000");
        }
        if (fromInclusive != null && untilExclusive != null
                && !fromInclusive.isBefore(untilExclusive)) {
            throw new IllegalArgumentException("time interval must be nonempty and increasing");
        }
    }

    public static TraceQuery latest(int limit) {
        return new TraceQuery(null, null, null, null, null, null, limit);
    }

    boolean matches(AuthorizationTraceEvent event) {
        return (requestId == null || requestId.equals(event.requestId()))
                && (protocol == null || protocol == event.protocol())
                && (outcome == null || outcome == event.outcome())
                && (reason == null || reason == event.reason())
                && (fromInclusive == null || !event.decidedAt().isBefore(fromInclusive))
                && (untilExclusive == null || event.decidedAt().isBefore(untilExclusive));
    }
}
