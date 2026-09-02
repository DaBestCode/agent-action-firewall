/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

/**
 * Transport-neutral input to authorization request binding.
 *
 * <p>The permitted implementations normalize transport metadata while preserving the exact action
 * payload bytes. This keeps protocol parsing outside the authorization engine.</p>
 */
public sealed interface CanonicalAction permits HttpAction, McpToolAction {
    ActionProtocol protocol();

    String operation();

    String resource();
}
