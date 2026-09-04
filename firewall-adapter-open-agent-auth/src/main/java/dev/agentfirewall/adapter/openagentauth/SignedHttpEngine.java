/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.agentfirewall.core.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static dev.agentfirewall.core.AuthorizationReason.*;

/** Firewall-specific strict checks plus the pinned upstream parsers and real WPT validator. */
final class SignedHttpEngine implements AgentAuthorizationEngine {
    private final HttpAuthorizationProfile.Trust aoatTrust;
    private final HttpAuthorizationProfile.Trust witTrust;
    private final Map<String, HttpAuthorizationProfile.Binding> bindings;
    private final Map<String, HttpAuthorizationProfile.Policy> policies;
    private final ReplayProtection replay;
    private final Clock clock;

    SignedHttpEngine(HttpAuthorizationProfile.Trust aoatTrust, HttpAuthorizationProfile.Trust witTrust,
            Map<String, HttpAuthorizationProfile.Binding> bindings,
            Map<String, HttpAuthorizationProfile.Policy> policies, ReplayProtection replay, Clock clock) {
        this.aoatTrust = aoatTrust; this.witTrust = witTrust; this.bindings = bindings;
        this.policies = policies; this.replay = replay; this.clock = clock;
    }

    @Override public AuthorizationDecision authorize(AgentActionRequest request) {
        try {
            require(request != null && request.action() != null, MALFORMED_ACTION);
            require(request.action() instanceof HttpAction, PROTOCOL_CONFUSION);
            var credentials = request.credentials();
            String rawAoat = credentials.agentOperationAuthorizationToken();
            String rawWit = credentials.workloadIdentityToken();
            String rawProof = credentials.workloadProofToken()
                    .orElseThrow(() -> new MappingFailure(MISSING_CREDENTIALS));
            Instant now = clock.instant();
            var aoat = verified(rawAoat, "aoat+jwt", aoatTrust.key(),
                    AOAT_ALGORITHM_REJECTED, AOAT_SIGNATURE_INVALID);
            var wit = verified(rawWit, "wit+jwt", witTrust.key(),
                    WORKLOAD_IDENTITY_ALGORITHM_REJECTED, WORKLOAD_IDENTITY_INVALID);
            require(aoatTrust.issuer().equals(aoat.getIssuer()), AOAT_ISSUER_MISMATCH);
            require(List.of(aoatTrust.audience()).equals(aoat.getAudience()), AOAT_AUDIENCE_MISMATCH);
            require(witTrust.issuer().equals(wit.getIssuer())
                    && List.of(witTrust.audience()).equals(wit.getAudience()), WORKLOAD_IDENTITY_INVALID);
            times(aoat, now, AOAT_EXPIRED, AOAT_NOT_YET_VALID, AOAT_LIFETIME_EXCEEDED);
            times(wit, now, WORKLOAD_IDENTITY_EXPIRED, WORKLOAD_IDENTITY_INVALID, WORKLOAD_IDENTITY_LIFETIME_EXCEEDED);
            // Reject the claim even when empty: delegation is not supported by this profile.
            require(!aoat.getClaims().containsKey("delegation_chain"), DELEGATION_CHAIN_INVALID);
            require(java.util.Set.of("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "agent_identity",
                    "agent_operation_authorization").containsAll(aoat.getClaims().keySet()), PROTOCOL_CONFUSION);
            var authorization = aoat.getJSONObjectClaim("agent_operation_authorization");
            require(authorization != null && authorization.keySet().equals(java.util.Set.of("policy_id")), PROTOCOL_CONFUSION);
            var cnf = wit.getJSONObjectClaim("cnf");
            require(cnf != null && cnf.get("jwk") instanceof Map<?, ?>, WORKLOAD_IDENTITY_INVALID);
            @SuppressWarnings("unchecked")
            var proofKey = ECKey.parse((Map<String, Object>) cnf.get("jwk"));
            require(!proofKey.isPrivate() && Curve.P_256.equals(proofKey.getCurve())
                    && JWSAlgorithm.ES256.equals(proofKey.getAlgorithm()), WORKLOAD_IDENTITY_INVALID);
            var proof = verified(rawProof, "wpt+jwt", JWSAlgorithm.ES256, new ECDSAVerifier(proofKey),
                    WORKLOAD_PROOF_INVALID, WORKLOAD_PROOF_INVALID);
            times(proof, now, WORKLOAD_PROOF_INVALID, WORKLOAD_PROOF_INVALID, WORKLOAD_PROOF_INVALID);
            require(List.of(aoatTrust.audience()).equals(proof.getAudience()), WORKLOAD_PROOF_INVALID);
            require(hash(rawWit).equals(proof.getStringClaim("wth")), WORKLOAD_PROOF_INVALID);
            require(hash(rawAoat).equals(proof.getStringClaim("aaf_aoat_hash")), WORKLOAD_PROOF_INVALID);
            require("aaf-http-v1".equals(proof.getStringClaim("aaf_profile")), PROTOCOL_CONFUSION);
            require(request.requestDigest().equals(proof.getStringClaim("aaf_action_digest")),
                    REQUEST_DIGEST_MISMATCH);

            // Parse only after cryptographic verification and enforce upstream WPT validation too.
            var context = new OpenAgentAuthContextMapper().map(request);
            require(new WptValidator().validate(context.getWpt(), context.getWit()).isValid(),
                    WORKLOAD_PROOF_INVALID);
            var identity = context.getAgentOaToken().getAgentIdentity();
            var binding = bindings.get(identity.getId());
            require(binding != null && now.isBefore(binding.expiresAt())
                    && binding.humanSubject().equals(aoat.getSubject())
                    && binding.issuedTo().equals(identity.getIssuedTo())
                    && aoatTrust.issuer().equals(identity.getIssuer())
                    && binding.workloadSubject().equals(wit.getSubject()), WORKLOAD_BINDING_MISMATCH);
            String policyId = context.getAgentOaToken().getAuthorization().getPolicyId();
            var policy = policies.get(policyId);
            require(policy != null, POLICY_NOT_FOUND);
            require(binding.policyIds().contains(policyId)
                    && policy.actionDigests().contains(request.requestDigest()), POLICY_DENIED);
            // Reserve only after all checks; retain until proof expiry, not shorter AOAT/WIT expiry.
            var result = replay.checkAndStore(new ReplayKey(witTrust.issuer(), proof.getJWTID()),
                    proof.getExpirationTime().toInstant());
            require(result == ReplayCheckResult.ACCEPTED,
                    result == ReplayCheckResult.REPLAYED ? REPLAY_DETECTED : WORKLOAD_PROOF_INVALID);
            return decision(POLICY_MATCHED, List.of(policyId));
        } catch (MappingFailure rejected) {
            return decision(rejected.reason(), List.of());
        } catch (Exception rejected) {
            // Never expose parser exceptions, claims, keys, or token strings.
            return decision(AUTHORIZATION_ENGINE_FAILURE, List.of());
        }
    }

    private static JWTClaimsSet verified(String raw, String type, RSAPublicKey key,
            AuthorizationReason algorithmReason, AuthorizationReason signatureReason) throws Exception {
        return verified(raw, type, JWSAlgorithm.RS256, new RSASSAVerifier(key), algorithmReason, signatureReason);
    }

    private static JWTClaimsSet verified(String raw, String type, JWSAlgorithm algorithm, JWSVerifier verifier,
            AuthorizationReason algorithmReason, AuthorizationReason signatureReason) throws Exception {
        require(raw != null && !raw.isBlank() && raw.length() <= 65536, signatureReason);
        SignedJWT jwt;
        try { jwt = SignedJWT.parse(raw); }
        catch (java.text.ParseException invalid) { throw new MappingFailure(signatureReason); }
        var header = jwt.getHeader();
        require(algorithm.equals(header.getAlgorithm()), algorithmReason);
        require(header.getType() != null && type.equals(header.getType().toString())
                && header.getCriticalParams() == null && header.isBase64URLEncodePayload()
                && header.getJWKURL() == null && header.getJWK() == null
                && header.getX509CertURL() == null, signatureReason);
        require(jwt.verify(verifier), signatureReason);
        return jwt.getJWTClaimsSet();
    }

    private static void times(JWTClaimsSet claims, Instant now, AuthorizationReason expired,
            AuthorizationReason future, AuthorizationReason lifetime) {
        require(claims.getExpirationTime() != null && now.isBefore(claims.getExpirationTime().toInstant()), expired);
        require(claims.getIssueTime() != null && !claims.getIssueTime().toInstant().isAfter(now)
                && claims.getIssueTime().before(claims.getExpirationTime())
                && (claims.getNotBeforeTime() == null || !claims.getNotBeforeTime().toInstant().isAfter(now)), future);
        require(claims.getExpirationTime().toInstant().isBefore(now.plusSeconds(601)), lifetime);
        require(!claims.getExpirationTime().toInstant().isAfter(claims.getIssueTime().toInstant().plusSeconds(600)), lifetime);
        require(claims.getJWTID() != null && !claims.getJWTID().isBlank()
                && claims.getJWTID().length() <= 256, future);
    }

    private static String hash(String token) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
    }

    private static void require(boolean condition, AuthorizationReason reason) {
        if (!condition) throw new MappingFailure(reason);
    }

    private AuthorizationDecision decision(AuthorizationReason reason, List<String> policyIds) {
        return new AuthorizationDecision(UUID.randomUUID().toString(), reason.outcome(), reason, clock.instant(), policyIds);
    }
}
