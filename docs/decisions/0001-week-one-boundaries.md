# ADR 0001 — Week 1 boundary review

Status: accepted locally, awaiting review and commit.

## Decisions

1. Core stays independent of frameworks, JSON libraries and Open Agent Auth. The test kit is a
   separate, test-scoped dependency; its exact-match engine must never become a runtime fallback.
2. Trace storage is bounded by count, field sizes and receipt age. Synchronization provides atomic
   eviction/query snapshots without introducing database dependencies. Durable storage remains Week 3.
3. Audit events contain controlled reasons, not free-form adapter explanations. Structural exclusion
   of credentials is not a guarantee that arbitrary string labels are free of secrets.
4. Validation errors reject invalid model construction; they are not authorization decisions.
   The future transport must map invalid input to a denial/error and never forward it.
5. Replay claims are a separate SPI. A real adapter must verify evidence before claiming it and must
   enforce a verified retention horizon; the in-memory store is neither distributed nor durable.
6. The Day 2 HTTP digest implementation had three confirmed problems during review: method case was
   folded, Java URI normalization collapsed repeated slashes, and IPv6 hosts gained duplicate
   brackets. HTTP methods are case-sensitive ([RFC 9110 section 9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1)).
   Local Java 17 checks confirmed the latter two behaviors.
7. Digest v2 preserves method spelling and raw path segments/encoding, while still normalizing
   scheme/host case, default ports and empty paths. The domain changes from v1 to v2; old digests must
   be regenerated, with no implicit v1 acceptance. The golden vector is independently calculated
   using Python's SHA-256 and big-endian framing and asserted by the Java test.

## Remaining limits and integration obligations

The digest models are not a gateway: adapters must bind the bytes actually forwarded and reject
unsupported headers/transformations. Only Content-Type is bound today; other policy-relevant HTTP
headers need an explicit future binding profile. MCP JSON canonicalization is still adapter work.
Authorization request attributes are not included in the action digest and must not silently stand
in for cryptographically bound parameters. A digest proves equality of representations, not consent,
authenticity or safe model intent.

The trace store exposes no network endpoint and has no tenant authorization. The JSON schema is a
wire-design artifact, not a tested serialization implementation. The test engine verifies only
literal test credentials and an exact action fixture. None of these milestones implies production
readiness or upstream protocol compliance.
