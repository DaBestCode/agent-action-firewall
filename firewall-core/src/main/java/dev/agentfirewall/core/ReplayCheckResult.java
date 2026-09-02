/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

/** Result of atomically claiming authorization evidence for one-time use. */
public enum ReplayCheckResult {
    ACCEPTED,
    REPLAYED,
    EXPIRED
}
