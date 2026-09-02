/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.util.Objects;
import java.util.Optional;

/**
 * Credentials presented with an agent action.
 *
 * <p>The class deliberately redacts its string representation. Raw token values must never be
 * copied to decision traces, exceptions, metrics, or application logs.</p>
 */
public final class PresentedCredentials {
    private static final String REDACTED = "[REDACTED]";

    private final String agentOperationAuthorizationToken;
    private final String workloadIdentityToken;
    private final String workloadProofToken;

    public PresentedCredentials(
            String agentOperationAuthorizationToken,
            String workloadIdentityToken,
            String workloadProofToken) {
        this.agentOperationAuthorizationToken = requireToken(
                agentOperationAuthorizationToken, "agentOperationAuthorizationToken");
        this.workloadIdentityToken = requireToken(workloadIdentityToken, "workloadIdentityToken");
        this.workloadProofToken = workloadProofToken;
    }

    public String agentOperationAuthorizationToken() {
        return agentOperationAuthorizationToken;
    }

    public String workloadIdentityToken() {
        return workloadIdentityToken;
    }

    public Optional<String> workloadProofToken() {
        return Optional.ofNullable(workloadProofToken);
    }

    @Override
    public String toString() {
        return "PresentedCredentials{" +
                "agentOperationAuthorizationToken='" + REDACTED + '\'' +
                ", workloadIdentityToken='" + REDACTED + '\'' +
                ", workloadProofToken='" + (workloadProofToken == null ? "absent" : REDACTED) + '\'' +
                '}';
    }

    private static String requireToken(String token, String name) {
        Objects.requireNonNull(token, name + " must not be null");
        if (token.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return token;
    }
}

