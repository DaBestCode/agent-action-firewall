/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.util.Objects;

/** Issuer-scoped identifier used to detect reuse of authorization evidence. */
public record ReplayKey(String issuer, String tokenId) {
    public ReplayKey {
        issuer = requireText(issuer, "issuer");
        tokenId = requireText(tokenId, "tokenId");
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
