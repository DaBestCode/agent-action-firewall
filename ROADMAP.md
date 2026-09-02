# Delivery roadmap

The plan assumes one focused developer and six weeks. Each week ends with a demonstrable, tested
increment rather than a partially connected subsystem.

## Week 1 — contracts, threat model, and executable core

**Day 1:** Repository setup, Apache-2.0 licensing, Maven structure, stable authorization interface,
fail-closed orchestration, credential redaction, attack-case schema, architecture and threat model.

**Day 2:** Define canonical MCP and HTTP action representations, SHA-256 request digest service,
reason-code taxonomy, and validation tests.

**Day 3:** Add replay-protection SPI plus in-memory implementation with expiry and concurrency tests.

**Day 4:** Define sanitized trace-event schema, in-memory trace repository, filtering, and retention
boundaries.

**Day 5:** Add contract-test kit for authorization engines and an intentionally small deterministic
test engine. Review Week 1 API and document decisions.

Exit criteria: the framework-neutral core compiles and passes tests; malformed inputs and engine
failures deny access; no credential can appear in a trace event.

## Week 2 — Open Agent Auth adapter and HTTP vertical slice

**Day 6:** Reproducibly build Open Agent Auth commit
`d75da121a66f8b2ae5be009a98e050fd1dc4c1e6` in an isolated local Maven repository.

**Day 7:** Map firewall credentials and action context to upstream AOAT/WIT/WPT validation APIs.

**Day 8:** Implement issuer, audience, time, workload-binding, and policy-decision mapping.

**Day 9:** Build the Spring Boot gateway filter and protected upstream test service.

**Day 10:** Run a Testcontainers/WireMock HTTP allow/deny flow and document upstream limitations.

Exit criteria: one HTTP action is allowed or denied through the pinned engine and emits a sanitized
trace.

## Week 3 — MCP enforcement and trace explorer backend

**Day 11:** Canonicalize MCP `tools/call` requests and bind tool name plus argument digest.

**Day 12:** Implement MCP proxy/interceptor and downstream forwarding.

**Day 13:** Add PostgreSQL trace storage and migrations.

**Day 14:** Add trace query API and human-to-agent correlation model.

**Day 15:** Build the first trace-explorer page with decision reasoning and redaction tests.

Exit criteria: an MCP tool call is enforced and its authorization lineage is inspectable without
exposing credentials.

## Week 4 — adversarial corpus

**Day 16:** Build fixture generator and schema validation.

**Day 17:** Add token tampering, issuer/audience, expiry, and algorithm cases.

**Day 18:** Add replay, identity-confusion, and cross-session context-leakage cases.

**Day 19:** Add policy escalation and MCP/HTTP protocol-confusion cases.

**Day 20:** Produce machine-readable and HTML attack reports in CI.

Exit criteria: a versioned corpus exercises every documented threat and fails the build on an
unexpected allow.

## Week 5 — delegation and observability

**Day 21:** Define delegation-chain verification contract and canonical signed-record format.

**Day 22:** Verify per-record AS signatures and JTI linkage.

**Day 23:** Enforce original-principal continuity and scope narrowing.

**Day 24:** Add OpenTelemetry spans, metrics, and safe structured logs.

**Day 25:** Add Grafana dashboard and delegation attack scenarios.

Exit criteria: forged, reordered, or broadened delegations are rejected and explained in traces.

## Week 6 — benchmark and public demo

**Day 26:** Create procurement demo with human consent, agent action, and resource server.

**Day 27:** Add delegated-agent scenario and visible denials.

**Day 28:** Benchmark p50/p95/p99 latency, throughput, and JWKS/replay-cache behavior.

**Day 29:** Harden configuration, container images, SBOM, dependency review, and documentation.

**Day 30:** Record demo, publish benchmark methodology, review security claims, and prepare v0.1.0.

