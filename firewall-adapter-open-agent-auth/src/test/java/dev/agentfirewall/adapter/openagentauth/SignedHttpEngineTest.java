/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.*;
import dev.agentfirewall.core.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static dev.agentfirewall.core.AuthorizationReason.*;

class SignedHttpEngineTest {
    private static final Instant NOW = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final RSAKey AUTHORITY = key();
    private static final RSAKey WORKLOAD = key();
    private static final ECKey PROOF = proofKey();
    private static final HttpAction ACTION = new HttpAction("POST", URI.create("https://service.example/buy?a=1"),
            "application/json", "{\"amount\":5}".getBytes(StandardCharsets.UTF_8));
    private static final String DIGEST = new ActionDigestService().digest(ACTION);

    @Test void allowsSignedBoundActionAndRejectsReplay() throws Exception {
        var engine = engine();
        var request = request(tokens(a -> {}, w -> {}, p -> {}), ACTION);
        var decision = engine.authorize(request);
        assertEquals(POLICY_MATCHED, decision.reason());
        assertEquals(List.of("buy"), decision.policyIds());
        assertEquals(REPLAY_DETECTED, engine.authorize(request).reason());
    }

    @Test void checksIssuerAudienceTimesAndDelegation() throws Exception {
        assertAoat(a -> a.issuer("other"), AOAT_ISSUER_MISMATCH);
        assertAoat(a -> a.audience("other"), AOAT_AUDIENCE_MISMATCH);
        assertAoat(a -> a.audience(List.of("https://service.example", "other")), AOAT_AUDIENCE_MISMATCH);
        assertAoat(a -> a.expirationTime(Date.from(NOW)), AOAT_EXPIRED);
        assertAoat(a -> a.notBeforeTime(Date.from(NOW.plusSeconds(1))), AOAT_NOT_YET_VALID);
        assertAoat(a -> a.issueTime(Date.from(NOW.plusSeconds(1))), AOAT_NOT_YET_VALID);
        assertAoat(a -> a.claim("delegation_chain", List.of()), DELEGATION_CHAIN_INVALID);
        assertAoat(a -> a.expirationTime(Date.from(NOW.plusSeconds(601))), AOAT_LIFETIME_EXCEEDED);
        assertAoat(a -> a.claim("unsupported_constraint", true), PROTOCOL_CONFUSION);
    }

    @Test void verifiesBindingsAndLocalPolicy() throws Exception {
        assertAoat(a -> a.subject("other-human"), WORKLOAD_BINDING_MISMATCH);
        assertAoat(a -> a.claim("agent_identity", Map.of("id", "binding", "issuer", "authority",
                "issued_to", "other|human")), WORKLOAD_BINDING_MISMATCH);
        assertAoat(a -> a.claim("agent_operation_authorization", Map.of("policy_id", "missing")), POLICY_NOT_FOUND);
        assertEquals(WORKLOAD_BINDING_MISMATCH, engine().authorize(request(
                tokens(a -> {}, w -> w.subject("other-workload"), p -> {}), ACTION)).reason());
        var deniedAction = new HttpAction("DELETE", URI.create(ACTION.target()), ACTION.mediaType(), ACTION.body());
        var denied = tokens(a -> {}, w -> {}, p -> p.claim("aaf_action_digest", new ActionDigestService().digest(deniedAction)));
        assertEquals(POLICY_DENIED, engine().authorize(request(denied, deniedAction)).reason());
    }

    @Test void bindsProofToAudienceTokensAndExactAction() throws Exception {
        for (String claim : List.of("wth", "aaf_aoat_hash", "aud")) {
            assertEquals(WORKLOAD_PROOF_INVALID, engine().authorize(request(
                    tokens(a -> {}, w -> {}, p -> p.claim(claim, "other")), ACTION)).reason());
        }
        assertEquals(PROTOCOL_CONFUSION, engine().authorize(request(
                tokens(a -> {}, w -> {}, p -> p.claim("aaf_profile", "other")), ACTION)).reason());
        var credentials = tokens(a -> {}, w -> {}, p -> {});
        assertEquals(REQUEST_DIGEST_MISMATCH, engine().authorize(request(credentials,
                new HttpAction("POST", URI.create(ACTION.target()), ACTION.mediaType(), new byte[0]))).reason());
        // Failed digest attempts must not consume the valid proof.
        var engine = engine();
        engine.authorize(request(credentials, new HttpAction("DELETE", URI.create(ACTION.target()), "", new byte[0])));
        assertTrue(engine.authorize(request(credentials, ACTION)).allowed());
    }

    @Test void rejectsWrongKeysTypesAndAlgorithms() throws Exception {
        var credentials = tokens(a -> {}, w -> {}, p -> {});
        var original = SignedJWT.parse(credentials.agentOperationAuthorizationToken());
        var forged = new SignedJWT(original.getHeader(), original.getJWTClaimsSet());
        forged.sign(new RSASSASigner(WORKLOAD));
        assertEquals(AOAT_SIGNATURE_INVALID, engine().authorize(request(new PresentedCredentials(
                forged.serialize(), credentials.workloadIdentityToken(), credentials.workloadProofToken().orElseThrow()), ACTION)).reason());
        var wrongType = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType("wit+jwt")).build(),
                original.getJWTClaimsSet());
        wrongType.sign(new RSASSASigner(AUTHORITY));
        assertEquals(AOAT_SIGNATURE_INVALID, engine().authorize(request(new PresentedCredentials(
                wrongType.serialize(), credentials.workloadIdentityToken(), credentials.workloadProofToken().orElseThrow()), ACTION)).reason());
        var wrongAlg = new SignedJWT(new JWSHeader(JWSAlgorithm.RS512), original.getJWTClaimsSet());
        wrongAlg.sign(new RSASSASigner(AUTHORITY));
        assertEquals(AOAT_ALGORITHM_REJECTED, engine().authorize(request(new PresentedCredentials(
                wrongAlg.serialize(), credentials.workloadIdentityToken(), credentials.workloadProofToken().orElseThrow()), ACTION)).reason());
    }

    @Test void onlyOneConcurrentRequestCanConsumeProof() throws Exception {
        var engine = engine();
        var request = request(tokens(a -> {}, w -> {}, p -> {}), ACTION);
        var executor = Executors.newFixedThreadPool(6);
        try {
            List<Callable<Boolean>> calls = new ArrayList<>();
            for (int i = 0; i < 12; i++) calls.add(() -> engine.authorize(request).allowed());
            int allowed = 0;
            for (var result : executor.invokeAll(calls)) if (result.get()) allowed++;
            assertEquals(1, allowed);
        } finally { executor.shutdownNow(); }
    }

    @Test void replayStoreFailureDeniesAndTraceExcludesCredentials() throws Exception {
        var credentials = tokens(a -> {}, w -> {}, p -> {});
        var store = new InMemoryAuthorizationTraceRepository(5, Duration.ofMinutes(1), CLOCK);
        var firewall = new AgentActionFirewall(engine((key, expiry) -> { throw new IllegalStateException("secret"); }), store, CLOCK);
        assertEquals(AUTHORIZATION_ENGINE_FAILURE, firewall.authorize(request(credentials, ACTION)).reason());
        String trace = store.find(TraceQuery.latest(1)).toString();
        assertFalse(trace.contains(credentials.agentOperationAuthorizationToken()));
        assertFalse(trace.contains("amount"));
    }

    private void assertAoat(Consumer<JWTClaimsSet.Builder> change, AuthorizationReason reason) throws Exception {
        assertEquals(reason, engine().authorize(request(tokens(change, w -> {}, p -> {}), ACTION)).reason());
    }

    private static AgentAuthorizationEngine engine() throws Exception {
        return engine(new InMemoryReplayProtection(CLOCK));
    }

    private static AgentAuthorizationEngine engine(ReplayProtection replay) throws Exception {
        return HttpAuthorizationProfile.create(
                new HttpAuthorizationProfile.Trust("authority", "https://service.example", AUTHORITY.toRSAPublicKey()),
                new HttpAuthorizationProfile.Trust("workloads", "https://service.example", WORKLOAD.toRSAPublicKey()),
                Map.of("binding", new HttpAuthorizationProfile.Binding("human", "idp|human", "workload",
                        NOW.plusSeconds(300), Set.of("buy"))),
                Map.of("buy", new HttpAuthorizationProfile.Policy(Set.of(DIGEST))), replay, CLOCK);
    }

    private static PresentedCredentials tokens(Consumer<JWTClaimsSet.Builder> aoatChange,
            Consumer<JWTClaimsSet.Builder> witChange, Consumer<JWTClaimsSet.Builder> proofChange) throws Exception {
        var aoat = base().issuer("authority").subject("human")
                .claim("agent_identity", Map.of("id", "binding", "issuer", "authority", "issued_to", "idp|human"))
                .claim("agent_operation_authorization", Map.of("policy_id", "buy"));
        aoatChange.accept(aoat);
        String rawAoat = sign(aoat, "aoat+jwt", AUTHORITY);
        var wit = base().issuer("workloads").subject("workload")
                .claim("cnf", Map.of("jwk", PROOF.toPublicJWK().toJSONObject()));
        witChange.accept(wit);
        String rawWit = sign(wit, "wit+jwt", WORKLOAD);
        var proof = base().claim("wth", hash(rawWit)).claim("aaf_aoat_hash", hash(rawAoat))
                .claim("aaf_profile", "aaf-http-v1").claim("aaf_action_digest", DIGEST);
        proofChange.accept(proof);
        return new PresentedCredentials(rawAoat, rawWit, sign(proof, "wpt+jwt", PROOF));
    }

    private static JWTClaimsSet.Builder base() {
        return new JWTClaimsSet.Builder().audience("https://service.example").jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)));
    }
    private static String sign(JWTClaimsSet.Builder claims, String type, JWK key) throws Exception {
        var algorithm = key instanceof RSAKey ? JWSAlgorithm.RS256 : JWSAlgorithm.ES256;
        var jwt = new SignedJWT(new JWSHeader.Builder(algorithm).type(new JOSEObjectType(type)).build(), claims.build());
        jwt.sign(key instanceof RSAKey rsa ? new RSASSASigner(rsa) : new ECDSASigner((ECKey) key)); return jwt.serialize();
    }
    private static String hash(String value) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII)));
    }
    private static AgentActionRequest request(PresentedCredentials credentials, HttpAction action) {
        return AgentActionRequest.fromAction("request", action, NOW, Map.of(), credentials, new ActionDigestService());
    }
    private static RSAKey key() {
        try { return new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate(); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
    private static ECKey proofKey() {
        try { return new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate(); }
        catch (Exception e) { throw new ExceptionInInitializerError(e); }
    }
}
