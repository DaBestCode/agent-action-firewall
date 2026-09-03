/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.adapter.openagentauth;

import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.model.VerificationResult;
import dev.agentfirewall.core.AgentActionRequest;
import dev.agentfirewall.core.AgentAuthorizationEngine;
import dev.agentfirewall.core.AuthorizationDecision;
import dev.agentfirewall.core.AuthorizationReason;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Internal Day 7 bridge. No public factory until Day 8 supplies reviewed trust/policy configuration.
 * Upstream types never enter the public firewall API.
 */
final class OpenAgentAuthEngine implements AgentAuthorizationEngine {
    static final List<String> LAYERS = List.of(
            "Layer 1: Workload Identity Validator",
            "Layer 2: Workload Proof Validator",
            "Layer 3: Agent Operation Authorization Validator",
            "Layer 4: Identity Consistency Validator",
            "Layer 5: Policy Evaluation Validator");
    private final FiveLayerVerifier verifier;
    private final Clock clock;

    OpenAgentAuthEngine(FiveLayerVerifier verifier, Clock clock) {
        this.verifier = Objects.requireNonNull(verifier);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public AuthorizationDecision authorize(AgentActionRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        try {
            if (!completePipeline()) {
                return decision(AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE);
            }
            var context = new OpenAgentAuthContextMapper().map(request);
            return decision(mapResult(verifier.verify(context)));
        } catch (MappingFailure rejected) {
            return decision(rejected.reason());
        } catch (RuntimeException failure) {
            // Do not forward upstream messages or log exceptions containing parsed claims.
            return decision(AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE);
        }
    }

    private boolean completePipeline() {
        var validators = verifier.getValidators();
        if (validators == null || validators.size() != LAYERS.size()) {
            return false;
        }
        for (int i = 0; i < LAYERS.size(); i++) {
            var validator = validators.get(i);
            if (validator == null || validator.getOrder() != i + 1
                    || !LAYERS.get(i).equals(validator.getName())) {
                return false;
            }
        }
        return true;
    }

    private AuthorizationReason mapResult(VerificationResult result) {
        if (result == null || result.getLayerResults() == null) {
            return AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE;
        }
        var layers = result.getLayerResults();
        if (layers.isEmpty() || layers.size() > LAYERS.size()) {
            return AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE;
        }
        for (int i = 0; i < layers.size(); i++) {
            var layer = layers.get(i);
            if (layer == null || layer.getResult() == null || layer.getOrder() != i + 1
                    || !LAYERS.get(i).equals(layer.getValidatorName())) {
                return AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE;
            }
            if (!layer.isPassed()) {
                if (result.isSuccess() || result.getFirstFailure() != layer || i != layers.size() - 1) {
                    return AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE;
                }
                // Map structural layer identity, not free-form upstream error text.
                return switch (i) {
                    case 0 -> AuthorizationReason.WORKLOAD_IDENTITY_INVALID;
                    case 1 -> AuthorizationReason.WORKLOAD_PROOF_INVALID;
                    case 2 -> AuthorizationReason.POLICY_DENIED;
                    case 3 -> AuthorizationReason.WORKLOAD_BINDING_MISMATCH;
                    case 4 -> AuthorizationReason.POLICY_DENIED;
                    default -> AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE;
                };
            }
        }
        return result.isSuccess() && result.getFirstFailure() == null && layers.size() == LAYERS.size()
                ? AuthorizationReason.POLICY_MATCHED : AuthorizationReason.AUTHORIZATION_ENGINE_FAILURE;
    }

    private AuthorizationDecision decision(AuthorizationReason reason) {
        return new AuthorizationDecision(UUID.randomUUID().toString(), reason.outcome(), reason,
                clock.instant(), List.of());
    }
}
