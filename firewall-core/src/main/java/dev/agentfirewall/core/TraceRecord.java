/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;
import java.util.Objects;

/** Versioned trace envelope. Receipt time, not caller-supplied event time, controls retention. */
public record TraceRecord(int schemaVersion, Instant recordedAt, AuthorizationTraceEvent event) {
    public static final int CURRENT_VERSION = 1;

    public TraceRecord {
        if (schemaVersion != CURRENT_VERSION) {
            throw new IllegalArgumentException("unsupported trace schema version");
        }
        Objects.requireNonNull(recordedAt, "recordedAt must not be null");
        Objects.requireNonNull(event, "event must not be null");
    }
}
