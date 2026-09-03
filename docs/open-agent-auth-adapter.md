# Open Agent Auth adapter — Days 6–7

## Status

The pinned core builds and the internal translation bridge compiles against it. There is deliberately
no public production factory yet. Day 8 must supply reviewed issuer/key/algorithm/audience/time
configuration, policy evaluation and signed-action binding before exposing one.

All upstream imports are confined to `firewall-adapter-open-agent-auth`. Its implementation classes
are package-private and implement our `AgentAuthorizationEngine`. The adapter module is opt-in via
the `open-agent-auth` Maven profile. Default core/test-kit builds do not require upstream artifacts.

## Build from the lock

Prerequisites: the reviewed Java 17 toolchain, Maven 3.9.16, Git, jq, shasum and tar. The verified JAR
hash was produced using OpenJDK 17.0.20.1. A different toolchain may require a reviewed hash update;
do not bypass a mismatch.

```bash
# Run from the firewall repository with Java 17 selected.
bash scripts/build-open-agent-auth.sh /path/to/local/open-agent-auth
bash scripts/verify-open-agent-auth.sh

# Repeat without network once both sets of dependencies are cached:
bash scripts/build-open-agent-auth.sh /path/to/local/open-agent-auth --offline
bash scripts/verify-open-agent-auth.sh --offline
```

The build script reads the full commit from `upstream/open-agent-auth.lock.json` and exports that
Git tree into a fresh ignored `.upstream/<commit>/build.*` directory. It does not checkout, edit or
build inside the supplied source repository. Only the upstream parent and core module run; samples,
frontend tools, integration-service scripts and models are not started.

Upstream tests are enabled. JaCoCo instrumentation and coverage thresholds are disabled for this
artifact build; this does not skip tests. The commit timestamp fixes JAR timestamps. A dedicated
Maven repository under the commit directory isolates the upstream SNAPSHOT from other checkouts.

Two fresh exports on 2026-09-02, the second offline, produced the same core JAR SHA-256:
`060fd02e5694e31f55e3f96fcf8008079bf07ff21c8af2d918e2209ea32c112c`.

Both runs reported 3,704 upstream tests, zero failures/errors and nine skipped tests. This verifies
the selected core build, not the full multi-module repository or every protocol claim. Upstream
emits deprecation/unchecked warnings and a missing failsafe-version warning for an unbuilt module.

The verification wrapper checks the JAR and both upstream POM hashes against the tracked lock before
running our reactor. Use the wrapper, not a direct profile invocation against an arbitrary Maven
cache. The lock is source/artifact pinning, not a complete transitive dependency lock or a guarantee
of hermetic builds on every OS. Generated sources, dependencies and receipts are local and ignored.

## Context mapping

| Firewall input | Upstream context |
|---|---|
| Raw AOAT | `AoatParser.parse(SignedJWT)` → `agentOaToken` |
| Raw WIT | `WitParser.parse(SignedJWT)` → `wit` |
| Raw WPT | `WptParser.parse(String)` → `wpt` |
| Immutable HTTP action | Actual method, full target including query, media type and strict UTF-8 body |
| Request timestamp | A fresh `Date` instance |
| Attributes | Nested `context` map, never arbitrary top-level fields |
| Request ID/digest | Namespaced `firewall` map with `action:v2` profile |

`AgentActionRequest.fromAction` now retains the immutable action. Construction validates the action
against its metadata and digest. The legacy metadata-only constructor remains available for existing
tests, but this adapter rejects it. Trace events still exclude action payloads and query parameters.

Missing WPT, malformed tokens, oversized token inputs, invalid UTF-8 and unsupported MCP actions fail
closed. Parsing a signed JWT is not signature verification. No tokens, raw exception messages,
unverified policy IDs or upstream error metadata are copied into firewall decisions.

## Structural guards and evidence

The adapter requires five known layers in order, and rejects empty/partial/contradictory success
reports. These are configuration/result guards, not proof that a validator implementation is trusted.

Confirmed source observations at the pin:

- An empty `DefaultFiveLayerVerifier` returns success because it sees no failed validator.
  [Source](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-core/src/main/java/com/alibaba/openagentauth/core/validation/impl/DefaultFiveLayerVerifier.java).
- `PolicyEvaluationValidator` merges context attributes with `input.putAll`. We nest untrusted
  attributes to avoid overwriting built-in user/request policy inputs.
  [Source](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-core/src/main/java/com/alibaba/openagentauth/core/validation/layer/PolicyEvaluationValidator.java).
- The upstream context has mutable token/date internals. We build fresh context objects per call.
  [Source](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-core/src/main/java/com/alibaba/openagentauth/core/validation/model/ValidationContext.java).

All 24 issue/PR entries, including closed entries, were inspected on 2026-09-02. Merged
[PR #20](https://github.com/alibaba/open-agent-auth/pull/20) already adds protocol conformance tests;
this project does not present those as a new upstream contribution. The separate delegation concern
in [issue #24](https://github.com/alibaba/open-agent-auth/issues/24) had no comments at inspection.
That question is not a maintainer acceptance decision; intent remains unclear.

## Test coverage and remaining boundaries

The 14 adapter test executions use real upstream token parsers and orchestrator, plus synthetic
validation layers. They exercise context mapping, malformed inputs, attribute isolation, all five
failure positions, empty/partial/null/inconsistent results, exception suppression, tracing, and the
six shared contract tests. They do not establish signature, issuer, audience, expiry, delegation or
policy correctness. The first fixture run exposed missing required AOAT claims; the fixtures were
corrected rather than relaxing parsing.

Day 8 must verify the actual signed digest against the forwarded action, configure real validators,
map precise validation reasons, and integrate replay retention using verified claims. Putting a
digest in context metadata alone does not authorize or authenticate it. Policy IDs are intentionally
omitted until they can be taken from verified evidence.

Upstream validators/parsers have their own logging, sometimes including exceptions or claims.
Suppressing messages in this bridge does not sanitize upstream logs. A reviewed logging policy,
safe configuration and adversarial log tests are required before production wiring.
