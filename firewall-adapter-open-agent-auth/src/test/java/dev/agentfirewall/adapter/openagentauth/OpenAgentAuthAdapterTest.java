/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import static org.junit.jupiter.api.Assertions.*;
import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.impl.DefaultFiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.VerificationResult;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.agentfirewall.core.*;
import dev.agentfirewall.testkit.AuthorizationEngineContract;
import dev.agentfirewall.testkit.AuthorizationEngineScenario;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * Boundary tests using actual upstream parsers/orchestrator and synthetic validation layers.
 * These are NOT cryptographic authorization acceptance tests.
 */
class OpenAgentAuthAdapterTest implements AuthorizationEngineContract {
    private static final Instant NOW = Instant.parse("2026-09-02T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Override
    public AuthorizationEngineScenario scenario() {
        try {
            var credentials = credentials();
            var allowed = request(credentials);
            var denied = AgentActionRequest.fromAction("denied",
                    new HttpAction("DELETE", URI.create("https://inventory.example/purchase"),
                            null, new byte[0]), NOW, Map.of(), credentials, new ActionDigestService());
            var altered = AgentActionRequest.fromAction("altered",
                    new HttpAction("POST", URI.create("https://inventory.example/purchase?currency=USD"),
                            "application/json", "{\"amount\":76}".getBytes(StandardCharsets.UTF_8)),
                    NOW, Map.of(), credentials, new ActionDigestService());
            var verifier = pipeline(-1);
            FiveLayerVerifier checked = new FiveLayerVerifier() {
                @Override public List<LayerValidator> getValidators() { return verifier.getValidators(); }
                @Override public void registerValidator(LayerValidator validator) { throw new UnsupportedOperationException(); }
                @Override public VerificationResult verify(ValidationContext context) {
                    Map<String, String> metadata = context.getAttribute("firewall");
                    if (!allowed.requestDigest().equals(metadata.get("requestDigest"))) {
                        // Synthetic binding gate for contract wiring only, not signed-claim verification.
                        return pipeline(1).verify(context);
                    }
                    return verifier.verify(context);
                }
            };
            return new AuthorizationEngineScenario(new OpenAgentAuthEngine(checked, CLOCK), allowed,
                    request(new PresentedCredentials("malformed-test-token", credentials.workloadIdentityToken(),
                            credentials.workloadProofToken().orElseThrow())), denied, altered);
        } catch (Exception failure) {
            throw new AssertionError("Could not construct test fixtures", failure);
        }
    }

    @Test
    void mapsActualHttpActionAndAllThreeOriginalTokens() throws Exception {
        var request = request(credentials());
        var context = new OpenAgentAuthContextMapper().map(request);
        assertEquals("POST", context.getHttpMethod());
        assertEquals("https://inventory.example/purchase?currency=USD", context.getHttpUri());
        assertEquals("{\"amount\":75}", context.getHttpBody());
        assertEquals("application/json", context.getHttpHeader("Content-Type"));
        assertEquals(Date.from(NOW), context.getRequestTimestamp());
        assertEquals(request.credentials().workloadIdentityToken(), context.getWit().getJwtString());
        assertEquals(request.credentials().workloadProofToken().orElseThrow(), context.getWpt().getJwtString());
        assertEquals(request.credentials().agentOperationAuthorizationToken(), context.getAgentOaToken().getJwtString());
        Map<String, String> firewall = context.getAttribute("firewall");
        assertEquals(request.requestDigest(), firewall.get("requestDigest"));
        assertEquals("action:v2", firewall.get("digestProfile"));
    }

    @Test
    void nestsAttributesInsteadOfOverwritingUpstreamPolicyInputs() throws Exception {
        var context = new OpenAgentAuthContextMapper().map(request(credentials()));
        assertNull(context.getAttribute("user"));
        assertNull(context.getAttribute("request"));
        Map<String, String> attributes = context.getAttribute("context");
        assertEquals("attacker", attributes.get("user"));
        assertEquals("attacker", attributes.get("request"));
        assertThrows(UnsupportedOperationException.class, () -> attributes.put("user", "changed"));
    }

    @Test
    void deniesMalformedTokensAndMissingProofWithoutEchoingCredentials() throws Exception {
        var valid = credentials();
        var engine = new OpenAgentAuthEngine(pipeline(-1), CLOCK);
        assertEquals(AuthorizationReason.WORKLOAD_IDENTITY_INVALID, engine.authorize(request(
                new PresentedCredentials(valid.agentOperationAuthorizationToken(), "secret-bad-wit",
                        valid.workloadProofToken().orElseThrow()))).reason());
        assertEquals(AuthorizationReason.WORKLOAD_PROOF_INVALID, engine.authorize(request(
                new PresentedCredentials(valid.agentOperationAuthorizationToken(), valid.workloadIdentityToken(),
                        "secret-bad-wpt"))).reason());
        var denied = engine.authorize(request(new PresentedCredentials("secret-bad-aoat",
                valid.workloadIdentityToken(), valid.workloadProofToken().orElseThrow())));
        assertEquals(AuthorizationReason.MALFORMED_ACTION, denied.reason());
        assertFalse(denied.toString().contains("secret-bad"));
        assertEquals(AuthorizationReason.MISSING_CREDENTIALS, engine.authorize(request(
                new PresentedCredentials(valid.agentOperationAuthorizationToken(), valid.workloadIdentityToken(),
                        null))).reason());
    }

    @Test
    void rejectsMetadataOnlyMcpAndNonUtf8Body() throws Exception {
        var input = request(credentials());
        var engine = new OpenAgentAuthEngine(pipeline(-1), CLOCK);
        var legacy = new AgentActionRequest(input.requestId(), input.protocol(), input.operation(),
                input.resource(), input.requestDigest(), NOW, input.attributes(), input.credentials());
        assertEquals(AuthorizationReason.MALFORMED_ACTION, engine.authorize(legacy).reason());
        var mcp = AgentActionRequest.fromAction("mcp", new McpToolAction("server", "tool", new byte[0]),
                NOW, Map.of(), input.credentials(), new ActionDigestService());
        assertEquals(AuthorizationReason.PROTOCOL_CONFUSION, engine.authorize(mcp).reason());
        var binary = AgentActionRequest.fromAction("binary",
                new HttpAction("POST", URI.create("https://inventory.example"), null, new byte[] {(byte) 0xff}),
                NOW, Map.of(), input.credentials(), new ActionDigestService());
        assertEquals(AuthorizationReason.MALFORMED_ACTION, engine.authorize(binary).reason());
    }

    @Test
    void runsRealUpstreamOrchestratorAndMapsEachFailingLayer() throws Exception {
        var request = request(credentials());
        var allowed = new OpenAgentAuthEngine(pipeline(-1), CLOCK).authorize(request);
        assertTrue(allowed.allowed());
        assertEquals(NOW, allowed.decidedAt());
        List<AuthorizationReason> reasons = List.of(AuthorizationReason.WORKLOAD_IDENTITY_INVALID,
                AuthorizationReason.WORKLOAD_PROOF_INVALID, AuthorizationReason.POLICY_DENIED,
                AuthorizationReason.WORKLOAD_BINDING_MISMATCH, AuthorizationReason.POLICY_DENIED);
        for (int i = 0; i < 5; i++) {
            var decision = new OpenAgentAuthEngine(pipeline(i), CLOCK).authorize(request);
            assertEquals(reasons.get(i), decision.reason());
            assertFalse(decision.toString().contains("sensitive upstream diagnostic"));
        }
    }

    @Test
    void rejectsUpstreamEmptyPipelineEvenThoughUpstreamReportsSuccess() throws Exception {
        var empty = new DefaultFiveLayerVerifier();
        assertTrue(empty.verify(ValidationContext.builder().build()).isSuccess());
        assertEquals(AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE,
                new OpenAgentAuthEngine(empty, CLOCK).authorize(request(credentials())).reason());
    }

    @Test
    void rejectsPartialOrContradictorySuccessNullAndExceptions() throws Exception {
        var request = request(credentials());
        var oneLayer = new VerificationResult.LayerResult(OpenAgentAuthEngine.LAYERS.get(0),
                LayerValidationResult.success(), 1);
        var failedLayer = new VerificationResult.LayerResult(OpenAgentAuthEngine.LAYERS.get(0),
                LayerValidationResult.failure("secret"), 1);
        for (VerificationResult result : new VerificationResult[] {
                null, new VerificationResult(true, List.of(), null),
                new VerificationResult(true, List.of(oneLayer), null),
                new VerificationResult(true, List.of(failedLayer), failedLayer)}) {
            assertEquals(AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE,
                    new OpenAgentAuthEngine(verifierReturning(ignored -> result), CLOCK).authorize(request).reason());
        }
        assertEquals(AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE, new OpenAgentAuthEngine(
                verifierReturning(ignored -> { throw new IllegalStateException("secret token"); }), CLOCK)
                .authorize(request).reason());
    }

    @Test
    void firewallTraceContainsNoActionPayloadOrCredentials() throws Exception {
        var request = request(credentials());
        var store = new InMemoryAuthorizationTraceRepository(10, java.time.Duration.ofMinutes(1), CLOCK);
        var firewall = new AgentActionFirewall(new OpenAgentAuthEngine(pipeline(-1), CLOCK), store, CLOCK);
        assertTrue(firewall.authorize(request).allowed());
        String trace = store.find(TraceQuery.latest(1)).toString();
        assertFalse(trace.contains(request.credentials().agentOperationAuthorizationToken()));
        assertFalse(trace.contains("currency=USD"));
        assertFalse(trace.contains("amount"));
        assertFalse(trace.contains("attacker"));
    }

    private static AgentActionRequest request(PresentedCredentials credentials) {
        return AgentActionRequest.fromAction("test-request",
                new HttpAction("POST", URI.create("https://inventory.example/purchase?currency=USD"),
                        "application/json", "{\"amount\":75}".getBytes(StandardCharsets.UTF_8)),
                NOW, Map.of("user", "attacker", "request", "attacker"), credentials, new ActionDigestService());
    }

    private static PresentedCredentials credentials() throws Exception {
        return new PresentedCredentials(signedParsingFixture("aoat"), signedParsingFixture("wit"), signedParsingFixture("wpt"));
    }

    private static String signedParsingFixture(String id) throws Exception {
        var claims = new JWTClaimsSet.Builder().issuer("https://test-issuer.example").subject("test-agent")
                .audience("https://inventory.example").jwtID("test-" + id).issueTime(Date.from(NOW))
                .expirationTime(Date.from(NOW.plusSeconds(300))).claim("wth", "test-hash")
                .claim("agent_identity", Map.of("id", "test-agent", "issuer", "https://test-issuer.example",
                        "issued_to", "test-workload"))
                .claim("agent_operation_authorization", Map.of("policy_id", "test-policy"))
                .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(new JOSEObjectType(id + "+jwt")).build(), claims);
        jwt.sign(new MACSigner("test-only-secret-never-for-production".getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    private static DefaultFiveLayerVerifier pipeline(int failingIndex) {
        var verifier = new DefaultFiveLayerVerifier();
        for (int i = 0; i < 5; i++) {
            int index = i;
            verifier.registerValidator(new LayerValidator() {
                @Override public String getName() { return OpenAgentAuthEngine.LAYERS.get(index); }
                @Override public double getOrder() { return index + 1; }
                @Override public LayerValidationResult validate(ValidationContext context) {
                    return index == failingIndex ? LayerValidationResult.failure("sensitive upstream diagnostic")
                            : LayerValidationResult.success();
                }
            });
        }
        return verifier;
    }

    private static FiveLayerVerifier verifierReturning(Function<ValidationContext, VerificationResult> function) {
        return new FiveLayerVerifier() {
            @Override public VerificationResult verify(ValidationContext context) { return function.apply(context); }
            @Override public List<LayerValidator> getValidators() { return pipeline(-1).getValidators(); }
            @Override public void registerValidator(LayerValidator validator) { throw new UnsupportedOperationException(); }
        };
    }
}
