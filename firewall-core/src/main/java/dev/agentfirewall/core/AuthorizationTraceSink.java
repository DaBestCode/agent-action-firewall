/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

/** Destination for sanitized authorization decisions. */
@FunctionalInterface
public interface AuthorizationTraceSink {
    AuthorizationTraceSink NOOP = event -> { };

    void record(AuthorizationTraceEvent event);
}
