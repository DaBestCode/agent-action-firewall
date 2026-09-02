/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.time.Instant;

/** Atomic replay-protection boundary implemented by local or distributed stores. */
@FunctionalInterface
public interface ReplayProtection {
    ReplayCheckResult checkAndStore(ReplayKey key, Instant expiresAt);
}
