/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import dev.agentfirewall.core.AuthorizationReason;

/** Internal controlled failure; no token text or upstream exception is retained. */
final class MappingFailure extends RuntimeException {
    private final AuthorizationReason reason;

    MappingFailure(AuthorizationReason reason) {
        super(reason.explanation());
        this.reason = reason;
    }

    AuthorizationReason reason() {
        return reason;
    }
}
