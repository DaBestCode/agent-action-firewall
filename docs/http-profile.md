# Experimental signed HTTP profile — Days 8–9

## Scope and implementation decisions

`HttpAuthorizationProfile.create(...)` returns the core `AgentAuthorizationEngine` interface.
Its configuration exposes only JDK keys, strings, immutable bindings/policies, `Clock`, and the
firewall replay SPI. No upstream types escape. Trust keys are administrator-provisioned; no token
header or claim can initiate network discovery. Replacing a trust configuration requires creating
a new engine while preserving its shared replay store.

This is **aaf-http-v1**, a firewall-specific interoperability profile, not an assertion of full OAA,
WIMSE, OAuth or OIDC conformance. It reuses the pinned upstream parsers and real `WptValidator`.
The adapter performs its own strict signature/claim/binding checks and exact-digest local policy
evaluation. It does **not** invoke the upstream five-layer factory, OPA, or a remote binding service.
The old package-private five-layer bridge and its synthetic tests remain distinct.

Why this split: optional binding checks and incomplete delegation verification cannot establish
our firewall's guarantees. A small explicit profile is easier to reason about than silently accepting
every upstream token shape. Unsupported claims/flows deny rather than downgrade.

## Token contract

All tokens are compact signed JWTs, at most 65,536 characters. Only the exact types and algorithms
below are accepted. Remote/embedded header keys and critical header extensions are rejected.
`kid` is not a key-discovery mechanism: verification always uses the configured issuer key.

| Token | Header | Required signed content |
|---|---|---|
| AOAT | `typ=aoat+jwt`, `alg=RS256` | Exact configured `iss`, singleton `aud`, human `sub`, `iat`, `exp`, `jti`, `agent_identity`, `agent_operation_authorization` |
| WIT | `typ=wit+jwt`, `alg=RS256` | Exact configured `iss`, singleton `aud`, workload `sub`, `iat`, `exp`, `jti`, public P-256 `cnf.jwk` with `alg=ES256` |
| WPT | `typ=wpt+jwt`, `alg=ES256` | Resource singleton `aud`, `iat`, `exp`, `jti`, `wth`, and the three custom claims below |

Issuer RSA keys must be at least 2048 bits. The WPT signature is verified against the public key in
the already-verified WIT, and then checked again through upstream WPT validation.

Custom WPT claims:

- `aaf_profile`: exactly `aaf-http-v1`.
- `aaf_aoat_hash`: unpadded base64url SHA-256 of the exact ASCII compact AOAT.
- `aaf_action_digest`: the complete `sha256:...` value from [action:v2](action-digest.md).

`wth` is unpadded base64url SHA-256 of the exact compact WIT. All tokens require a nonblank JTI
of at most 256 characters. `iat` must not be in the future, optional `nbf` must have arrived,
`exp` must be strictly later than now, and lifetime cannot exceed 600 seconds. Dedicated AOAT and
workload-identity lifetime reason codes distinguish excessive validity from an already-expired token. There is no clock
skew allowance. Validation uses the injected clock; upstream WPT expiration also uses system time,
so deployments must keep clocks synchronized. Historical-clock simulation cannot override upstream time.

AOAT top-level claims are limited to the table plus optional `nbf`. Any `delegation_chain` claim,
even empty, is denied. Authorization contains **only** `policy_id`; inline policy/scope extensions
are not silently ignored. The administrator's binding is keyed by `agent_identity.id` and matches
the complete `issued_to` string, identity issuer, AOAT human subject, and WIT workload subject.
Binding expiry and allowed policy IDs are enforced. A policy authorizes only its exact action
digests, including method, target/query, media type and body. This is not wildcard policy evaluation.

After all checks, the engine atomically reserves `(workload issuer, WPT jti)` until WPT expiry.
An invalid action does not consume a valid proof; concurrent identical valid requests allow at
most one. A store exception/null/expired result denies. The in-memory implementation is suitable
only for one process and loses history on restart; distributed/persistent replay is not implemented.
Valid short-lived proofs can still grow the store; ingress rate limiting is required before deployment.

## Spring Boot transport

`firewall-gateway-http` is an **in-process resource-server filter**, not a network reverse proxy.
Register `FirewallRegistration.allRoutes(new ActionFirewallFilter(...))` as an explicit bean in a
dedicated stateless Boot application, supplying a real `AgentActionFirewall` and administrator-owned
public origin. There is no auto-created engine or allow-all default. Registration covers `/*`,
all dispatcher types, runs at highest precedence, and disables async. Non-REQUEST dispatches deny.
Spring's [FilterRegistrationBean documentation](https://docs.spring.io/spring-boot/3.3/api/java/org/springframework/boot/web/servlet/FilterRegistrationBean.html)
describes the explicit Servlet registration mechanism used here.

Credentials arrive in single-valued `X-Agent-AOAT`, `X-Agent-WIT`, `X-Agent-WPT` headers.
Host/Forwarded headers never select the authorized target. Request IDs and times are server-generated.
The filter buffers at most the configured body limit (maximum 1 MiB), computes the digest from those
bytes, and passes only that buffered body downstream after allowance.

Intentional transport restrictions:

- Root-context application; paths contain only ASCII letters, digits, slash, underscore and hyphen.
  Repeated slashes, percent encoding, dot segments and semicolon parameters reject.
- Query length is at most 4096 characters and its exact raw representation is signed.
- JSON media type, optional UTF-8 charset, or absent media type only; compressed/form/multipart
  bodies are unsupported. The signed adapter rejects non-UTF-8 bodies.
- Downstream header access exposes only Content-Type and computed Content-Length. Cookies,
  authorization credentials, identity headers, and forwarding headers are hidden. Servlet identity
  accessors are cleared; sessions, async, and parameter-map APIs are unsupported.
- Controllers should consume `@RequestBody byte[]` and explicitly interpret the bound raw query.
  This is not a sandbox against trusted Java code unwrapping the servlet request. Existing security
  filters, container principals, attributes, routing rules and alternate ingress need separate review.
- Pre-authorization malformed inputs return generic 400/413/415 errors; authorization denials return
  403. These early malformed requests do not yet generate core authorization traces. Allowed/denied
  engine decisions do; no body, query or credential enters their trace. Generic responses use no-store.

Do not expose this prototype publicly. TLS termination, slow-client timeouts, header limits, access-log
redaction, response policy, distributed replay, key rotation/revocation and dependency vulnerability
review are not complete. Keep upstream logging disabled (`logging.level.com.alibaba.openagentauth=OFF`)
because its validators can log token objects/claims. Application code must not log incoming headers.
Boot 3.3.11 matches the pin for compatibility testing, not a claim of current production support.

## Evidence at the pinned commit

Confirmed from local source and signed tests:

- `IdentityConsistencyValidator` skips binding verification without a binding store.
  [Source](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-core/src/main/java/com/alibaba/openagentauth/core/validation/layer/IdentityConsistencyValidator.java).
- `OperationAuthorizationValidator` checks delegation structure and signature presence, not the
  cryptographic signature of every record.
  [Source](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-core/src/main/java/com/alibaba/openagentauth/core/validation/layer/OperationAuthorizationValidator.java).
- `WptValidator.convertToJWK` throws for RSA conversion. A real RSA-proof fixture was denied;
  changing the profile to P-256/ES256 makes the real upstream validation succeed.
  [Source](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-core/src/main/java/com/alibaba/openagentauth/core/protocol/wimse/wpt/WptValidator.java).

Local evidence: `SignedHttpEngine.java`, `SignedHttpEngineTest.java` under
`firewall-adapter-open-agent-auth/src/{main,test}/java/dev/agentfirewall/adapter/openagentauth/`, and
`ActionFirewallFilterTest.java`, `ProtectedServiceTest.java` under
`firewall-gateway-http/src/test/java/dev/agentfirewall/gateway/http/`.

History review includes closed entries and merged [PR #20](https://github.com/alibaba/open-agent-auth/pull/20);
the related [delegation issue #24](https://github.com/alibaba/open-agent-auth/issues/24) is not maintainer
approval of this design. Maintainer intent remains unclear. This is independent downstream work,
not a proposed upstream contribution. The choice of a strict local profile is our design judgment.

## Verification

Run `bash scripts/verify-open-agent-auth.sh --offline` after dependencies have been cached.
The wrapper validates the upstream pin/checksums and runs all five modules. The embedded Boot test
binds a temporary **127.0.0.1** port and closes its context on completion; sandboxed runners may need
loopback-socket permission. It sends generated real signed credentials, observes tamper denial,
one exact-body allowance, replay denial and missing-credential rejection, and checks service call
count plus sanitized traces. No fixed private keys, tokens, models or containers are committed.

Containerized/WireMock verification remains Day 10. Explorer, persistent traces, executable attack
corpus and delegation remain later milestones; these tests do not replace them.
