/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/** Thread-safe replay protection for tests and single-process deployments. */
public final class InMemoryReplayProtection implements ReplayProtection {
    private final ConcurrentHashMap<ReplayKey, Instant> claims = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryReplayProtection(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public ReplayCheckResult checkAndStore(ReplayKey key, Instant expiresAt) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Instant now = clock.instant();
        if (!expiresAt.isAfter(now)) {
            return ReplayCheckResult.EXPIRED;
        }

        AtomicReference<ReplayCheckResult> result = new AtomicReference<>();
        claims.compute(key, (ignored, existingExpiry) -> {
            if (existingExpiry == null || !existingExpiry.isAfter(now)) {
                result.set(ReplayCheckResult.ACCEPTED);
                return expiresAt;
            }
            result.set(ReplayCheckResult.REPLAYED);
            return existingExpiry;
        });
        return result.get();
    }

    /** Removes expired entries and returns the number removed. */
    public int purgeExpired() {
        Instant now = clock.instant();
        int removed = 0;
        for (var entry : claims.entrySet()) {
            if (!entry.getValue().isAfter(now)
                    && claims.remove(entry.getKey(), entry.getValue())) {
                removed++;
            }
        }
        return removed;
    }

    public int size() {
        return claims.size();
    }
}
