/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class InMemoryAuthorizationTraceRepositoryTest {
    private static final Instant NOW = Instant.parse("2026-09-02T12:00:00Z");

    @Test
    void storesVersionedImmutableSnapshotsInInsertionOrder() {
        var store = store(10, Clock.fixed(NOW, ZoneOffset.UTC));
        store.record(event("first", AuthorizationReason.POLICY_MATCHED, NOW));
        store.record(event("second", AuthorizationReason.POLICY_DENIED, NOW.minusSeconds(60)));
        var snapshot = store.find(TraceQuery.latest(1));
        assertEquals("second", snapshot.get(0).event().requestId());
        assertEquals(1, snapshot.get(0).schemaVersion());
        assertEquals(NOW, snapshot.get(0).recordedAt());
        assertThrows(UnsupportedOperationException.class, snapshot::clear);
        store.record(event("third", AuthorizationReason.POLICY_MATCHED, NOW));
        assertEquals("second", snapshot.get(0).event().requestId());
    }

    @Test
    void appliesAllFiltersAndHalfOpenDecisionTimeRangeBeforeLimit() {
        var store = store(10, Clock.fixed(NOW, ZoneOffset.UTC));
        store.record(event("wanted", AuthorizationReason.POLICY_DENIED, NOW));
        store.record(event("wanted", AuthorizationReason.POLICY_DENIED, NOW.plusSeconds(10)));
        store.record(event("other", AuthorizationReason.POLICY_DENIED, NOW.plusSeconds(5)));
        store.record(event("wanted", AuthorizationReason.POLICY_MATCHED, NOW.plusSeconds(5)));
        var matches = store.find(new TraceQuery("wanted", ActionProtocol.MCP,
                AuthorizationOutcome.DENY, AuthorizationReason.POLICY_DENIED,
                NOW, NOW.plusSeconds(10), 1));
        assertEquals(1, matches.size());
        assertEquals(NOW, matches.get(0).event().decidedAt());
        assertTrue(store.find(new TraceQuery(null, ActionProtocol.HTTP, null, null,
                null, null, 10)).isEmpty());
        assertTrue(store.find(new TraceQuery(null, null, null, AuthorizationReason.REPLAY_DETECTED,
                null, null, 10)).isEmpty());
    }

    @Test
    void evictsOldestInsertionAtCapacity() {
        var store = store(2, Clock.fixed(NOW, ZoneOffset.UTC));
        store.record(event("first", AuthorizationReason.POLICY_MATCHED, NOW.plusSeconds(100)));
        store.record(event("second", AuthorizationReason.POLICY_MATCHED, NOW));
        store.record(event("third", AuthorizationReason.POLICY_MATCHED, NOW));
        assertEquals(List.of("third", "second"), store.find(TraceQuery.latest(10)).stream()
                .map(record -> record.event().requestId()).toList());
    }

    @Test
    void expiresExactlyAtReceiptTimeBoundaryRegardlessOfEventTime() {
        var now = new AtomicReference<>(NOW);
        var store = store(10, clock(now));
        store.record(event("future", AuthorizationReason.POLICY_MATCHED, NOW.plus(Duration.ofDays(365))));
        now.set(NOW.plusSeconds(59));
        assertEquals(1, store.find(TraceQuery.latest(10)).size());
        now.set(NOW.plusSeconds(60));
        assertTrue(store.find(TraceQuery.latest(10)).isEmpty());
    }

    @Test
    void writesAndExplicitCleanupPurgeExpiredRecords() {
        var now = new AtomicReference<>(NOW);
        var store = store(10, clock(now));
        store.record(event("first", AuthorizationReason.POLICY_MATCHED, NOW));
        now.set(NOW.plusSeconds(60));
        assertEquals(1, store.purgeExpired());
        assertEquals(0, store.purgeExpired());
        store.record(event("second", AuthorizationReason.POLICY_MATCHED, NOW));
        now.set(NOW.plusSeconds(120));
        store.record(event("third", AuthorizationReason.POLICY_MATCHED, NOW));
        assertEquals(1, store.find(TraceQuery.latest(10)).size());
        assertEquals("third", store.find(TraceQuery.latest(10)).get(0).event().requestId());
    }

    @Test
    void concurrentWritersAndReadersRespectCapacityAndReturnSafeSnapshots() throws Exception {
        var store = store(40, Clock.fixed(NOW, ZoneOffset.UTC));
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int i = 0; i < 200; i++) {
                int id = i;
                tasks.add(() -> {
                    store.record(event("request-" + id, AuthorizationReason.POLICY_MATCHED, NOW));
                    assertTrue(store.find(TraceQuery.latest(100)).size() <= 40);
                    return null;
                });
            }
            for (Future<Void> result : executor.invokeAll(tasks, 10, TimeUnit.SECONDS)) {
                result.get(1, TimeUnit.SECONDS);
            }
            assertEquals(40, store.find(TraceQuery.latest(100)).size());
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void rejectsInvalidConfigurationQueriesAndInputs() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        assertThrows(IllegalArgumentException.class, () -> store(0, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryAuthorizationTraceRepository(1, Duration.ZERO, clock));
        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryAuthorizationTraceRepository(1, Duration.ofSeconds(-1), clock));
        assertThrows(IllegalArgumentException.class, () -> TraceQuery.latest(0));
        assertThrows(IllegalArgumentException.class, () -> TraceQuery.latest(1001));
        assertThrows(IllegalArgumentException.class,
                () -> new TraceQuery(null, null, null, null, NOW, NOW, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new TraceQuery(" ", null, null, null, null, null, 1));
        assertThrows(NullPointerException.class, () -> store(1, clock).record(null));
        assertThrows(NullPointerException.class, () -> store(1, clock).find(null));
        assertThrows(IllegalArgumentException.class,
                () -> new TraceRecord(2, NOW, event("x", AuthorizationReason.POLICY_MATCHED, NOW)));
    }

    private static InMemoryAuthorizationTraceRepository store(int capacity, Clock clock) {
        return new InMemoryAuthorizationTraceRepository(capacity, Duration.ofMinutes(1), clock);
    }

    private static AuthorizationTraceEvent event(String id, AuthorizationReason reason, Instant time) {
        return new AuthorizationTraceEvent(id, ActionProtocol.MCP, "tools/call", "inventory/purchase",
                "sha256:" + "a".repeat(64), NOW, "decision-" + id, reason.outcome(), reason,
                time, List.of("policy-1"));
    }

    private static Clock clock(AtomicReference<Instant> now) {
        return new Clock() {
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return Clock.fixed(now.get(), zone); }
            @Override public Instant instant() { return now.get(); }
        };
    }
}
