/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

/** Controlled authorization reason taxonomy safe for APIs and sanitized traces. */
public enum AuthorizationReason {
    POLICY_MATCHED(AuthorizationOutcome.ALLOW, "The action matches an applicable authorization policy."),
    MALFORMED_ACTION(AuthorizationOutcome.DENY, "The action representation is invalid."),
    MISSING_CREDENTIALS(AuthorizationOutcome.DENY, "Required authorization credentials are missing."),
    AOAT_ALGORITHM_REJECTED(AuthorizationOutcome.DENY, "The authorization token algorithm is not allowed."),
    AOAT_SIGNATURE_INVALID(AuthorizationOutcome.DENY, "The authorization token signature is invalid."),
    AOAT_ISSUER_MISMATCH(AuthorizationOutcome.DENY, "The authorization token issuer is not trusted."),
    AOAT_AUDIENCE_MISMATCH(AuthorizationOutcome.DENY, "The authorization token audience does not match."),
    AOAT_NOT_YET_VALID(AuthorizationOutcome.DENY, "The authorization token is not yet valid."),
    AOAT_EXPIRED(AuthorizationOutcome.DENY, "The authorization token has expired."),
    WORKLOAD_IDENTITY_ALGORITHM_REJECTED(
            AuthorizationOutcome.DENY, "The workload identity algorithm is not allowed."),
    WORKLOAD_IDENTITY_INVALID(AuthorizationOutcome.DENY, "The workload identity is invalid."),
    WORKLOAD_IDENTITY_EXPIRED(AuthorizationOutcome.DENY, "The workload identity has expired."),
    WORKLOAD_BINDING_MISMATCH(AuthorizationOutcome.DENY, "The workload identity binding does not match."),
    WORKLOAD_PROOF_INVALID(AuthorizationOutcome.DENY, "The workload proof is invalid."),
    REQUEST_DIGEST_MISMATCH(AuthorizationOutcome.DENY, "The action does not match the authorized digest."),
    POLICY_NOT_FOUND(AuthorizationOutcome.DENY, "No applicable authorization policy was found."),
    POLICY_DENIED(AuthorizationOutcome.DENY, "An applicable policy denied the action."),
    SCOPE_EXCEEDED(AuthorizationOutcome.DENY, "The action exceeds the authorized scope."),
    REPLAY_DETECTED(AuthorizationOutcome.DENY, "The authorization evidence has already been used."),
    PROTOCOL_CONFUSION(AuthorizationOutcome.DENY, "The evidence is not valid for this action protocol."),
    DELEGATION_SIGNATURE_INVALID(AuthorizationOutcome.DENY, "A delegation signature is invalid."),
    DELEGATION_SCOPE_EXPANDED(AuthorizationOutcome.DENY, "A delegation expands its parent scope."),
    DELEGATION_CHAIN_INVALID(AuthorizationOutcome.DENY, "The delegation chain is invalid."),
    AUTHORIZATION_ENGINE_FAILURE(AuthorizationOutcome.DENY, "Authorization could not be established.");

    private final AuthorizationOutcome outcome;
    private final String explanation;

    AuthorizationReason(AuthorizationOutcome outcome, String explanation) {
        this.outcome = outcome;
        this.explanation = explanation;
    }

    public AuthorizationOutcome outcome() {
        return outcome;
    }

    public String explanation() {
        return explanation;
    }
}
