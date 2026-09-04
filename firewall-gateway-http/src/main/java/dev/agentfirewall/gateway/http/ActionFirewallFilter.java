/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.gateway.http;

import dev.agentfirewall.core.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Clock;
import java.util.*;

/** Synchronous, in-process HTTP enforcement. Only body, target, method and media type are forwarded. */
public final class ActionFirewallFilter implements Filter {
    public static final String AOAT_HEADER = "X-Agent-AOAT";
    public static final String WIT_HEADER = "X-Agent-WIT";
    public static final String WPT_HEADER = "X-Agent-WPT";
    private final AgentActionFirewall firewall;
    private final String origin;
    private final int maxBodyBytes;
    private final Clock clock;

    /** The origin is administrator-owned; Host and forwarding headers never select an audience. */
    public ActionFirewallFilter(AgentActionFirewall firewall, URI publicOrigin, int maxBodyBytes, Clock clock) {
        this.firewall = Objects.requireNonNull(firewall); this.clock = Objects.requireNonNull(clock);
        var action = new HttpAction("GET", publicOrigin, "", new byte[0]);
        if (!publicOrigin.getRawPath().isEmpty() && !"/".equals(publicOrigin.getRawPath())
                || publicOrigin.getRawQuery() != null) throw new IllegalArgumentException("Origin must have no path or query");
        this.origin = action.target().substring(0, action.target().length() - 1);
        if (maxBodyBytes < 1 || maxBodyBytes > 1048576) throw new IllegalArgumentException("Body limit must be 1..1048576");
        this.maxBodyBytes = maxBodyBytes;
    }

    @Override public void doFilter(ServletRequest input, ServletResponse output, FilterChain chain)
            throws IOException, ServletException {
        if (!(input instanceof HttpServletRequest request) || !(output instanceof HttpServletResponse response)) {
            throw new ServletException("HTTP required");
        }
        if (request.getDispatcherType() != DispatcherType.REQUEST || request.isAsyncStarted()) {
            deny(response, 403); return;
        }
        AgentActionRequest actionRequest;
        byte[] body;
        String mediaType;
        try {
            // Deliberately small routing grammar avoids decoding/normalization differences in containers.
            String path = request.getRequestURI();
            if (path == null || !path.matches("/[A-Za-z0-9/_-]*") || path.contains("//")
                    || request.getContextPath() == null || !request.getContextPath().isEmpty()
                    || !Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS").contains(request.getMethod())
                    || request.getHeader("Content-Encoding") != null) {
                deny(response, 400); return;
            }
            var credentials = new PresentedCredentials(single(request, AOAT_HEADER, true),
                    single(request, WIT_HEADER, true), single(request, WPT_HEADER, true));
            mediaType = single(request, "Content-Type", false);
            if (!mediaType.isEmpty() && !mediaType.equalsIgnoreCase("application/json")
                    && !mediaType.equalsIgnoreCase("application/json;charset=UTF-8")
                    && !mediaType.equalsIgnoreCase("application/json; charset=UTF-8")) {
                deny(response, 415); return;
            }
            if (request.getContentLengthLong() > maxBodyBytes) { deny(response, 413); return; }
            body = request.getInputStream().readNBytes(maxBodyBytes + 1);
            if (body.length > maxBodyBytes) { deny(response, 413); return; }
            String query = request.getQueryString();
            if (query != null && query.length() > 4096) { deny(response, 400); return; }
            var action = new HttpAction(request.getMethod(), URI.create(origin + path + (query == null ? "" : "?" + query)), mediaType, body);
            actionRequest = AgentActionRequest.fromAction(UUID.randomUUID().toString(), action, clock.instant(),
                    Map.of(), credentials, new ActionDigestService());
        } catch (IllegalArgumentException invalid) {
            deny(response, 400); return;
        }
        var decision = firewall.authorize(actionRequest);
        response.setHeader("X-Firewall-Decision", decision.decisionId());
        response.setHeader("Cache-Control", "no-store");
        if (!decision.allowed()) { deny(response, 403); return; }
        // Only the verified, buffered body is available downstream; credential headers are absent.
        chain.doFilter(new BoundRequest(request, body, mediaType, URI.create(origin)), response);
    }

    private static String single(HttpServletRequest request, String name, boolean required) {
        var values = Collections.list(request.getHeaders(name));
        if (values.isEmpty() && !required) return "";
        if (values.size() != 1 || values.get(0).isBlank() || values.get(0).length() > 65536) {
            throw new IllegalArgumentException("Invalid header");
        }
        return values.get(0);
    }

    private static void deny(HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"request_rejected\"}");
    }

    private static final class BoundRequest extends HttpServletRequestWrapper {
        private final byte[] body;
        private final String mediaType;
        private final URI publicOrigin;
        BoundRequest(HttpServletRequest request, byte[] body, String mediaType, URI publicOrigin) {
            super(request); this.body = body; this.mediaType = mediaType; this.publicOrigin = publicOrigin;
        }
        @Override public String getScheme() { return publicOrigin.getScheme(); }
        @Override public String getServerName() { return publicOrigin.getHost(); }
        @Override public int getServerPort() { return publicOrigin.getPort() >= 0 ? publicOrigin.getPort() : (isSecure() ? 443 : 80); }
        @Override public boolean isSecure() { return "https".equals(publicOrigin.getScheme()); }
        @Override public StringBuffer getRequestURL() { return new StringBuffer(publicOrigin + getRequestURI()); }
        @Override public String getParameter(String name) { throw new IllegalStateException("Use bound body/query explicitly"); }
        @Override public String[] getParameterValues(String name) { throw new IllegalStateException("Use bound body/query explicitly"); }
        @Override public Enumeration<String> getParameterNames() { throw new IllegalStateException("Use bound body/query explicitly"); }
        @Override public Map<String, String[]> getParameterMap() { throw new IllegalStateException("Use bound body/query explicitly"); }
        @Override public Collection<Part> getParts() { throw new IllegalStateException("Multipart unsupported"); }
        @Override public Part getPart(String name) { throw new IllegalStateException("Multipart unsupported"); }
        @Override public String getHeader(String name) {
            if ("Content-Type".equalsIgnoreCase(name)) return mediaType.isEmpty() ? null : mediaType;
            if ("Content-Length".equalsIgnoreCase(name)) return Integer.toString(body.length);
            return null;
        }
        @Override public Enumeration<String> getHeaders(String name) {
            String value = getHeader(name);
            return Collections.enumeration(value == null ? List.of() : List.of(value));
        }
        @Override public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(mediaType.isEmpty() ? List.of("Content-Length") : List.of("Content-Type", "Content-Length"));
        }
        @Override public int getIntHeader(String name) { String value = getHeader(name); return value == null ? -1 : Integer.parseInt(value); }
        @Override public long getDateHeader(String name) { return -1; }
        @Override public Cookie[] getCookies() { return null; }
        @Override public Principal getUserPrincipal() { return null; }
        @Override public String getRemoteUser() { return null; }
        @Override public String getAuthType() { return null; }
        @Override public boolean isUserInRole(String role) { return false; }
        @Override public HttpSession getSession(boolean create) { if (create) throw new IllegalStateException("Sessions unsupported"); return null; }
        @Override public HttpSession getSession() { throw new IllegalStateException("Sessions unsupported"); }
        @Override public boolean isAsyncSupported() { return false; }
        @Override public AsyncContext startAsync() { throw new IllegalStateException("Async unsupported"); }
        @Override public AsyncContext startAsync(ServletRequest request, ServletResponse response) { throw new IllegalStateException("Async unsupported"); }
        @Override public String getContentType() { return mediaType.isEmpty() ? null : mediaType; }
        @Override public int getContentLength() { return body.length; }
        @Override public long getContentLengthLong() { return body.length; }
        @Override public String getCharacterEncoding() { return StandardCharsets.UTF_8.name(); }
        @Override public ServletInputStream getInputStream() {
            var stream = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public int read() { return stream.read(); }
                @Override public boolean isFinished() { return stream.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener listener) { throw new IllegalStateException("Async unsupported"); }
            };
        }
        @Override public BufferedReader getReader() { return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8)); }
    }
}
