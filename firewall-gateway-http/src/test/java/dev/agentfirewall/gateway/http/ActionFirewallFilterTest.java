/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.gateway.http;

import dev.agentfirewall.core.*;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import static org.junit.jupiter.api.Assertions.*;

class ActionFirewallFilterTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-03T12:00:00Z"), ZoneOffset.UTC);

    @Test void forwardsExactBoundBodyAndDropsAllUnboundHeaders() throws Exception {
        var seen = new AtomicReference<AgentActionRequest>();
        var request = request();
        request.setQueryString("a=1&a=2");
        request.addHeader("Host", "attacker.example");
        request.addHeader("Forwarded", "host=attacker.example");
        request.addHeader("Authorization", "secret");
        request.addHeader("Cookie", "session=secret");
        request.addHeader("X-Override-Method", "DELETE");
        request.setCookies(new Cookie("session", "secret"));
        var response = new MockHttpServletResponse();
        var reached = new AtomicBoolean();
        filter(action -> { seen.set(action); return allow(); }).doFilter(request, response, (input, output) -> {
            reached.set(true);
            var bound = (HttpServletRequest) input;
            assertArrayEquals(request.getContentAsByteArray(), bound.getInputStream().readAllBytes());
            for (String name : List.of("X-Agent-AOAT", "X-Agent-WIT", "X-Agent-WPT", "Authorization", "Cookie", "Forwarded", "X-Override-Method")) {
                assertNull(bound.getHeader(name)); assertFalse(bound.getHeaders(name).hasMoreElements());
            }
            assertEquals(Set.of("Content-Type", "Content-Length"), new HashSet<>(Collections.list(bound.getHeaderNames())));
            assertNull(bound.getCookies()); assertNull(bound.getSession(false)); assertNull(bound.getUserPrincipal());
            assertThrows(IllegalStateException.class, bound::startAsync);
            assertThrows(IllegalStateException.class, () -> bound.getParameter("a"));
            assertEquals("https://service.example/buy", bound.getRequestURL().toString());
            assertEquals("a=1&a=2", bound.getQueryString());
        });
        assertTrue(reached.get());
        assertEquals("https://service.example/buy?a=1&a=2", ((HttpAction) seen.get().action()).target());
        assertEquals(200, response.getStatus());
        assertEquals("no-store", response.getHeader("Cache-Control"));
    }

    @Test void denialAndEngineFailureNeverReachProtectedServiceAndAreTraced() throws Exception {
        for (boolean failure : List.of(false, true)) {
            var store = new InMemoryAuthorizationTraceRepository(5, Duration.ofMinutes(5), CLOCK);
            var firewall = new AgentActionFirewall(action -> {
                if (failure) throw new IllegalStateException("secret");
                return AuthorizationDecision.deny("id", AuthorizationReason.POLICY_DENIED, CLOCK.instant());
            }, store, CLOCK);
            var filter = new ActionFirewallFilter(firewall, URI.create("https://service.example"), 100, CLOCK);
            var response = new MockHttpServletResponse();
            filter.doFilter(request(), response, (input, output) -> fail("Denied request forwarded"));
            assertEquals(403, response.getStatus());
            assertEquals("{\"error\":\"request_rejected\"}", response.getContentAsString());
            assertEquals(1, store.find(TraceQuery.latest(5)).size());
        }
    }

    @Test void rejectsMissingDuplicateAndOversizeCredentialsBeforeEngine() throws Exception {
        var absent = request(); absent.removeHeader("X-Agent-AOAT");
        var duplicate = request(); duplicate.addHeader("X-Agent-WPT", "other");
        var huge = request(); huge.removeHeader("X-Agent-WIT"); huge.addHeader("X-Agent-WIT", "x".repeat(65537));
        for (var request : List.of(absent, duplicate, huge)) rejected(request, 400);
    }

    @Test void rejectsAmbiguousRoutingCompressedBodiesAndRedispatch() throws Exception {
        for (String path : List.of("//buy", "/a/../buy", "/b%75y", "/buy;x=1")) {
            var request = request(); request.setRequestURI(path); rejected(request, 400);
        }
        var compressed = request(); compressed.addHeader("Content-Encoding", "gzip"); rejected(compressed, 400);
        var forward = request(); forward.setDispatcherType(DispatcherType.FORWARD); rejected(forward, 403);
        var context = request(); context.setContextPath("/app"); rejected(context, 400);
        var form = request(); form.setContentType("application/x-www-form-urlencoded"); rejected(form, 415);
    }

    @Test void enforcesBodyLimitWithKnownAndUnknownLength() throws Exception {
        var large = request(); large.setContent(new byte[101]); rejected(large, 413);
        var chunked = new MockHttpServletRequest("POST", "/buy") {
            @Override public long getContentLengthLong() { return -1; }
        };
        headers(chunked); chunked.setContent(new byte[101]); rejected(chunked, 413);
    }

    @Test void validatesConfigurationAndRegistersEveryRoute() {
        var filter = filter(action -> allow());
        var registration = FirewallRegistration.allRoutes(filter);
        assertEquals(List.of("/*"), new ArrayList<>(registration.getUrlPatterns()));
        assertEquals(Integer.MIN_VALUE, registration.getOrder());
        assertFalse(registration.isAsyncSupported());
        assertThrows(IllegalArgumentException.class, () -> new ActionFirewallFilter(
                new AgentActionFirewall(action -> allow(), event -> {}, CLOCK), URI.create("https://service.example/path"), 100, CLOCK));
    }

    private static void rejected(MockHttpServletRequest request, int status) throws Exception {
        var response = new MockHttpServletResponse();
        filter(action -> { fail("Invalid request reached engine"); return allow(); }).doFilter(request, response,
                (input, output) -> fail("Invalid request forwarded"));
        assertEquals(status, response.getStatus());
    }
    private static ActionFirewallFilter filter(AgentAuthorizationEngine engine) {
        return new ActionFirewallFilter(new AgentActionFirewall(engine, event -> {}, CLOCK),
                URI.create("https://service.example"), 100, CLOCK);
    }
    private static AuthorizationDecision allow() {
        return new AuthorizationDecision("decision", AuthorizationOutcome.ALLOW, AuthorizationReason.POLICY_MATCHED, CLOCK.instant(), List.of("buy"));
    }
    private static MockHttpServletRequest request() {
        var request = new MockHttpServletRequest("POST", "/buy"); headers(request);
        request.setContent("{\"amount\":5}".getBytes(StandardCharsets.UTF_8)); return request;
    }
    private static void headers(MockHttpServletRequest request) {
        request.addHeader("X-Agent-AOAT", "test-aoat"); request.addHeader("X-Agent-WIT", "test-wit");
        request.addHeader("X-Agent-WPT", "test-proof"); request.setContentType("application/json");
    }
}
