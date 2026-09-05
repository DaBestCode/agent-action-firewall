/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.gateway.http;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;
import dev.agentfirewall.adapter.openagentauth.HttpAuthorizationProfile;
import dev.agentfirewall.core.*;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.web.bind.annotation.*;
import static org.junit.jupiter.api.Assertions.*;

class ProtectedServiceTest {
    private static final URI ORIGIN = URI.create("https://service.example");
    private static final byte[] BODY = "{\"amount\":5}".getBytes(StandardCharsets.UTF_8);

    @Test void realSignedHttpFlowAllowsOnceDeniesTamperingAndRecordsTraces() throws Exception {
        verifyFlow(null);
    }

    static void verifyFlow(URI downstream) throws Exception {
        var clock = Clock.systemUTC();
        var now = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var issuer = new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate();
        var workload = new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate();
        var proofKey = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        var action = new HttpAction("POST", ORIGIN.resolve("/buy"), "application/json", BODY);
        String digest = new ActionDigestService().digest(action);
        var engine = HttpAuthorizationProfile.create(
                new HttpAuthorizationProfile.Trust("authority", ORIGIN.toString(), issuer.toRSAPublicKey()),
                new HttpAuthorizationProfile.Trust("workloads", ORIGIN.toString(), workload.toRSAPublicKey()),
                Map.of("binding", new HttpAuthorizationProfile.Binding("human", "idp|human", "workload",
                        now.plusSeconds(300), Set.of("buy"))),
                Map.of("buy", new HttpAuthorizationProfile.Policy(Set.of(digest))), new InMemoryReplayProtection(clock), clock);
        String aoat = sign(base(now).issuer("authority").subject("human")
                .claim("agent_identity", Map.of("id", "binding", "issuer", "authority", "issued_to", "idp|human"))
                .claim("agent_operation_authorization", Map.of("policy_id", "buy")), "aoat+jwt", issuer);
        String wit = sign(base(now).issuer("workloads").subject("workload")
                .claim("cnf", Map.of("jwk", proofKey.toPublicJWK().toJSONObject())), "wit+jwt", workload);
        String proof = sign(base(now).claim("wth", hash(wit)).claim("aaf_aoat_hash", hash(aoat))
                .claim("aaf_profile", "aaf-http-v1").claim("aaf_action_digest", digest), "wpt+jwt", proofKey);
        var traces = new InMemoryAuthorizationTraceRepository(10, Duration.ofMinutes(5), clock);
        var firewall = new AgentActionFirewall(engine, traces, clock);
        try (var context = new SpringApplicationBuilder(Service.class)
                .properties(Map.of("server.port", "0", "server.address", "127.0.0.1", "spring.main.banner-mode", "off",
                        "logging.level.root", "OFF", "logging.level.com.alibaba.openagentauth", "OFF"))
                .initializers(application -> {
                    application.getBeanFactory().registerSingleton("firewall", firewall);
                    application.getBeanFactory().registerSingleton("testDownstream", new Downstream(downstream));
                }).run()) {
            int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
            var uri = URI.create("http://127.0.0.1:" + port + "/buy");
            var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            // Tampering must fail without consuming the correct proof.
            assertEquals(403, send(client, uri, aoat, wit, proof, "{}".getBytes(StandardCharsets.UTF_8)).statusCode());
            var allowed = send(client, uri, aoat, wit, proof, BODY);
            assertEquals(200, allowed.statusCode());
            assertArrayEquals(BODY, allowed.body());
            assertEquals(403, send(client, uri, aoat, wit, proof, BODY).statusCode());
            var missing = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofByteArray(BODY)).build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(400, missing.statusCode());
            assertEquals(1, context.getBean(Service.class).calls.get());
            var records = traces.find(TraceQuery.latest(10));
            assertEquals(3, records.size());
            assertFalse(records.toString().contains(aoat));
            assertFalse(records.toString().contains("amount"));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @RestController
    static class Service {
        final AtomicInteger calls = new AtomicInteger();
        private final Downstream downstream;
        Service(Downstream downstream) { this.downstream = downstream; }
        @Bean FilterRegistrationBean<ActionFirewallFilter> registration(AgentActionFirewall firewall) {
            return FirewallRegistration.allRoutes(new ActionFirewallFilter(firewall, ORIGIN, 1024, Clock.systemUTC()));
        }
        @PostMapping(value = "/buy", produces = "application/json")
        byte[] buy(@RequestBody byte[] body, HttpServletRequest request) throws Exception {
            assertNull(request.getHeader("X-Agent-AOAT"));
            assertNull(request.getHeader("Authorization"));
            calls.incrementAndGet();
            if (downstream.uri() != null) {
                var response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build().send(
                        HttpRequest.newBuilder(downstream.uri()).timeout(Duration.ofSeconds(5))
                                .header("Content-Type", request.getContentType())
                                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
                assertEquals(200, response.statusCode());
                return response.body();
            }
            return body;
        }
    }

    record Downstream(URI uri) { }

    private static HttpResponse<byte[]> send(HttpClient client, URI uri, String aoat, String wit, String proof, byte[] body) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5))
                .header("X-Agent-AOAT", aoat).header("X-Agent-WIT", wit).header("X-Agent-WPT", proof)
                .header("Authorization", "must-not-leak").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
    }
    private static JWTClaimsSet.Builder base(Instant now) {
        return new JWTClaimsSet.Builder().audience(ORIGIN.toString()).jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300)));
    }
    private static String sign(JWTClaimsSet.Builder claims, String type, JWK key) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(key instanceof RSAKey ? JWSAlgorithm.RS256 : JWSAlgorithm.ES256)
                .type(new JOSEObjectType(type)).build(), claims.build());
        jwt.sign(key instanceof RSAKey rsa ? new RSASSASigner(rsa) : new ECDSASigner((ECKey) key)); return jwt.serialize();
    }
    private static String hash(String value) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII)));
    }
}
