/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/** Canonical security-relevant representation of an HTTP request. */
public final class HttpAction implements CanonicalAction {
    private static final Pattern METHOD = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

    private final String method;
    private final String resource;
    private final String target;
    private final String mediaType;
    private final byte[] body;

    public HttpAction(String method, URI target, String mediaType, byte[] body) {
        this.method = normalizeMethod(method);
        this.target = normalizeTarget(target);
        this.resource = stripQuery(this.target);
        this.mediaType = normalizeMediaType(mediaType);
        this.body = Arrays.copyOf(Objects.requireNonNull(body, "body must not be null"), body.length);
    }

    @Override
    public ActionProtocol protocol() {
        return ActionProtocol.HTTP;
    }

    @Override
    public String operation() {
        return method;
    }

    @Override
    public String resource() {
        return resource;
    }

    /** Full normalized target used only in the action digest; it must not be copied to traces. */
    public String target() {
        return target;
    }

    public String mediaType() {
        return mediaType;
    }

    public byte[] body() {
        return Arrays.copyOf(body, body.length);
    }

    private static String normalizeMethod(String method) {
        Objects.requireNonNull(method, "method must not be null");
        if (!METHOD.matcher(method).matches()) {
            throw new IllegalArgumentException("method must be a valid HTTP token");
        }
        return method;
    }

    private static String normalizeTarget(URI target) {
        Objects.requireNonNull(target, "target must not be null");
        String scheme = target.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("target must use an absolute http or https URI");
        }
        if (target.getHost() == null) {
            throw new IllegalArgumentException("target must contain a valid host");
        }
        if (target.getUserInfo() != null || target.getFragment() != null) {
            throw new IllegalArgumentException("target must not contain user-info or a fragment");
        }

        String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
        String host = target.getHost().toLowerCase(Locale.ROOT);
        int port = target.getPort();
        if (port > 65535) {
            throw new IllegalArgumentException("target port must be at most 65535");
        }
        boolean defaultPort = (normalizedScheme.equals("http") && port == 80)
                || (normalizedScheme.equals("https") && port == 443);
        String path = target.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        String query = target.getRawQuery() == null ? "" : "?" + target.getRawQuery();
        return normalizedScheme + "://" + host
                + (port < 0 || defaultPort ? "" : ":" + port)
                + path
                + query;
    }

    private static String normalizeMediaType(String mediaType) {
        if (mediaType == null) {
            return "";
        }
        if (mediaType.indexOf('\r') >= 0 || mediaType.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("mediaType must not contain line breaks");
        }
        return mediaType.trim();
    }

    private static String stripQuery(String target) {
        int queryStart = target.indexOf('?');
        return queryStart < 0 ? target : target.substring(0, queryStart);
    }
}
