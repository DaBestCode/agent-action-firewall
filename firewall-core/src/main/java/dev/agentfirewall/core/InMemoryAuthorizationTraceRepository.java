/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;

/** Bounded, single-process store. Synchronized operations provide consistent query snapshots. */
public final class InMemoryAuthorizationTraceRepository implements AuthorizationTraceRepository {
    private final Deque<TraceRecord> records = new ArrayDeque<>();
    private final int capacity;
    private final Duration retention;
    private final Clock clock;

    public InMemoryAuthorizationTraceRepository(int capacity, Duration retention, Clock clock) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.retention = Objects.requireNonNull(retention, "retention must not be null");
        if (retention.isZero() || retention.isNegative()) {
            throw new IllegalArgumentException("retention must be positive");
        }
        this.capacity = capacity;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public synchronized void record(AuthorizationTraceEvent event) {
        Objects.requireNonNull(event, "event must not be null");
        Instant now = clock.instant();
        purgeAt(now);
        if (records.size() == capacity) {
            records.removeFirst();
        }
        records.addLast(new TraceRecord(TraceRecord.CURRENT_VERSION, now, event));
    }

    @Override
    public synchronized List<TraceRecord> find(TraceQuery query) {
        Objects.requireNonNull(query, "query must not be null");
        purgeAt(clock.instant());
        List<TraceRecord> result = new ArrayList<>();
        var iterator = records.descendingIterator();
        while (iterator.hasNext() && result.size() < query.limit()) {
            TraceRecord record = iterator.next();
            if (query.matches(record.event())) {
                result.add(record);
            }
        }
        return List.copyOf(result);
    }

    @Override
    public synchronized int purgeExpired() {
        return purgeAt(clock.instant());
    }

    private int purgeAt(Instant now) {
        int before = records.size();
        records.removeIf(record -> Duration.between(record.recordedAt(), now).compareTo(retention) >= 0);
        return before - records.size();
    }
}
