/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import com.alibaba.openagentauth.core.protocol.wimse.wit.WitParser;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptParser;
import com.alibaba.openagentauth.core.token.aoat.AoatParser;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.nimbusds.jwt.SignedJWT;
import dev.agentfirewall.core.AgentActionRequest;
import dev.agentfirewall.core.AuthorizationReason;
import dev.agentfirewall.core.HttpAction;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

/** Parsing and context translation only. Parsing a signed JWT does NOT verify its signature. */
final class OpenAgentAuthContextMapper {
    ValidationContext map(AgentActionRequest request) {
        if (request.action() == null) {
            throw new MappingFailure(AuthorizationReason.MALFORMED_ACTION);
        }
        if (!(request.action() instanceof HttpAction http)) {
            throw new MappingFailure(AuthorizationReason.PROTOCOL_CONFUSION);
        }
        var credentials = request.credentials();
        String proof = credentials.workloadProofToken()
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new MappingFailure(AuthorizationReason.MISSING_CREDENTIALS));
        // Bound parsing inputs; upstream parsers are not given arbitrarily large token strings.
        if (credentials.agentOperationAuthorizationToken().length() > 65536
                || credentials.workloadIdentityToken().length() > 65536 || proof.length() > 65536) {
            throw new MappingFailure(AuthorizationReason.MALFORMED_ACTION);
        }

        var builder = ValidationContext.builder();
        try {
            builder.wit(new WitParser().parse(SignedJWT.parse(credentials.workloadIdentityToken())));
        } catch (ParseException | RuntimeException invalid) {
            throw new MappingFailure(AuthorizationReason.WORKLOAD_IDENTITY_INVALID);
        }
        try {
            builder.wpt(new WptParser().parse(proof));
        } catch (ParseException | RuntimeException invalid) {
            throw new MappingFailure(AuthorizationReason.WORKLOAD_PROOF_INVALID);
        }
        try {
            builder.agentOaToken(new AoatParser().parse(
                    SignedJWT.parse(credentials.agentOperationAuthorizationToken())));
        } catch (ParseException | RuntimeException invalid) {
            throw new MappingFailure(AuthorizationReason.MALFORMED_ACTION);
        }

        String body;
        try {
            body = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(http.body())).toString();
        } catch (CharacterCodingException invalid) {
            throw new MappingFailure(AuthorizationReason.MALFORMED_ACTION);
        }
        // Never merge caller attributes at top level: upstream policy input uses putAll(attributes).
        return builder.httpMethod(http.operation()).httpUri(http.target()).httpBody(body)
                .httpHeaders(http.mediaType().isEmpty() ? Map.of() : Map.of("Content-Type", http.mediaType()))
                .requestTimestamp(Date.from(request.requestedAt()))
                .addAttribute("operationType", request.operation())
                .addAttribute("resourceId", request.resource())
                .addAttribute("context", Map.copyOf(request.attributes()))
                .addAttribute("firewall", Map.of("requestId", request.requestId(),
                        "requestDigest", request.requestDigest(), "digestProfile", "action:v2"))
                .build();
    }
}
