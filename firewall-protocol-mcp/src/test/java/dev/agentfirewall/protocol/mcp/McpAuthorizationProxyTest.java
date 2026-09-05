/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

import dev.agentfirewall.core.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class McpAuthorizationProxyTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-05T12:00:00Z"), ZoneOffset.UTC);
    private static final PresentedCredentials CREDS = new PresentedCredentials("secret-aoat", "secret-wit", "secret-wpt");

    @Test void forwardsOnlyCanonicalAuthorizedRequestAndTracesIt() {
        var seen = new AtomicReference<byte[]>(); var server = new AtomicReference<String>();
        var store = new InMemoryAuthorizationTraceRepository(5, Duration.ofMinutes(1), CLOCK);
        var proxy = proxy(request -> allow(), store, (id, body) -> { server.set(id); seen.set(body); return bytes("{\"ok\":true}"); });
        var result = proxy.handle("inventory", request("{\"z\":1.0,\"a\":2}"), CREDS);
        assertEquals(McpProxyResult.Status.FORWARDED, result.status()); assertEquals("inventory", server.get());
        assertEquals("{\"id\":7,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"a\":2,\"z\":1},\"name\":\"buy\"}}", text(seen.get()));
        assertEquals("{\"ok\":true}", text(result.response())); assertNotNull(result.decisionId());
        var event = store.find(TraceQuery.latest(1)).get(0).event();
        assertEquals(ActionProtocol.MCP, event.protocol()); assertEquals("inventory/buy", event.resource());
        assertFalse(event.toString().contains("secret")); assertFalse(result.toString().contains("ok"));
    }

    @Test void denialNeverCallsDownstreamAndReturnsCorrelatedGenericError() {
        var calls = new AtomicInteger();
        var proxy = proxy(request -> AuthorizationDecision.deny("deny", AuthorizationReason.POLICY_DENIED, CLOCK.instant()),
                event -> {}, (id, body) -> { calls.incrementAndGet(); return body; });
        var result = proxy.handle("inventory", request("{}"), CREDS);
        assertEquals(McpProxyResult.Status.REJECTED, result.status()); assertEquals(0, calls.get());
        assertEquals("deny", result.decisionId());
        assertEquals("{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32001,\"message\":\"authorization_denied\"}}", text(result.response()));
    }

    @Test void engineFailureDeniesAndMalformedInputNeverCallsEngineOrDownstream() {
        var calls = new AtomicInteger(); var engines = new AtomicInteger();
        var failure = proxy(request -> { throw new IllegalStateException("secret"); }, event -> {},
                (id, body) -> { calls.incrementAndGet(); return body; });
        assertEquals(McpProxyResult.Status.REJECTED, failure.handle("inventory", request("{}"), CREDS).status());
        var malformed = proxy(request -> { engines.incrementAndGet(); return allow(); }, event -> {},
                (id, body) -> { calls.incrementAndGet(); return body; });
        var result = malformed.handle("inventory", bytes("not json"), CREDS);
        assertEquals(McpProxyResult.Status.MALFORMED, result.status()); assertNull(result.decisionId());
        assertEquals(0, calls.get()); assertEquals(0, engines.get()); assertTrue(text(result.response()).contains("\"id\":null"));
    }

    @Test void downstreamFailuresAreGenericAndResponseIsBounded() {
        for (McpForwarder forwarder : new McpForwarder[] {(id, body) -> { throw new IllegalStateException("secret endpoint"); },
                (id, body) -> null, (id, body) -> new byte[0], (id, body) -> new byte[1048577]}) {
            var result = proxy(request -> allow(), event -> {}, forwarder).handle("inventory", request("{}"), CREDS);
            assertEquals(McpProxyResult.Status.DOWNSTREAM_FAILURE, result.status());
            assertFalse(result.toString().contains("secret")); assertTrue(text(result.response()).contains("downstream_unavailable"));
        }
    }

    @Test void defensiveCopiesPreventPostAuthorizationMutation() {
        var original = request("{}"); var forwarded = new AtomicReference<byte[]>();
        var proxy = proxy(request -> { original[0] = 'x'; return allow(); }, event -> {},
                (id, body) -> { assertEquals('{', body[0]); forwarded.set(body.clone()); body[0] = 'x'; return bytes("response"); });
        var result = proxy.handle("inventory", original, CREDS);
        assertEquals(McpProxyResult.Status.FORWARDED, result.status()); assertEquals('{', forwarded.get()[0]);
        byte[] response = result.response(); response[0] = 'x'; assertEquals("response", text(result.response()));
    }

    private static McpAuthorizationProxy proxy(AgentAuthorizationEngine engine, AuthorizationTraceSink sink, McpForwarder forwarder) {
        return new McpAuthorizationProxy(new McpCallCanonicalizer(), new AgentActionFirewall(engine, sink, CLOCK), forwarder, CLOCK);
    }
    private static AuthorizationDecision allow() { return new AuthorizationDecision("allow", AuthorizationOutcome.ALLOW,
            AuthorizationReason.POLICY_MATCHED, CLOCK.instant(), List.of("buy")); }
    private static byte[] request(String arguments) { return bytes("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"buy\",\"arguments\":" + arguments + "}}"); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] value) { return new String(value, StandardCharsets.UTF_8); }
}
