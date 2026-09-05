# Trace storage and data boundary

Day 4 adds an in-memory implementation of `AuthorizationTraceRepository`. Day 13 adds the optional
[PostgreSQL implementation](postgres-traces.md). Neither alone establishes production-grade audit
evidence. `TraceRecord` wraps the existing event with schema version 1
and a receipt timestamp from the store's clock.

The proposed JSON wire shape is in [trace-record.schema.json](schema/trace-record.schema.json).
There is no JSON codec or trace HTTP endpoint yet. A future codec must encode the record components
explicitly, use enum names and ISO-8601 timestamps, and reject unknown properties/versions. Convenience
methods such as `reasonCode()` are not additional wire fields. Java bounds use UTF-16 code units,
so they can be stricter than JSON Schema's Unicode character counts.

## Storage behavior

- Capacity and retention are mandatory and positive.
- Every write, read, and explicit purge removes expired records.
- Retention expires at receipt time plus the configured duration, inclusive.
- Event timestamps do not control retention; future-dated events cannot extend their lifetime.
- Capacity pressure evicts the oldest insertion, independently of event time.
- Queries return immutable snapshots in reverse insertion order, including equal timestamps.
- Request ID, protocol, outcome and reason are exact-match filters combined with AND.
- Decision-time filters use a half-open interval: from inclusive, until exclusive.
- Filtering occurs before the result limit, which must be between 1 and 1000.
- Writes and queries are synchronized. This is deliberately simple, bounded, single-process storage.
- Expiry is lazy: idle stores retain expired objects until the next operation or an explicit purge.
  A service with a wall-clock deletion requirement must schedule purges.
- Clock rollback can delay age-based expiry, but cannot resurrect removed records.
- Duplicate decision IDs are retained as separate insertions; this store is not an idempotency service.

## Sanitization limits

Raw credential objects, request attributes, payloads and free-form explanations do not enter the
event schema. HTTP queries and fragments are removed at the trace boundary even for directly
constructed requests. HTTP user-info is rejected without echoing the URI in an exception.
Label lengths, control characters, digest shape, policy-count limits and reason/outcome consistency
are validated before storage.

This is data minimization, not secret detection. Caller-controlled request IDs, policy IDs and path
segments can still contain sensitive data. Transport adapters must supply opaque correlation IDs and
classified resource labels. Trace authorization, tenant isolation, path templating, persistence,
HTML escaping and access controls are required before exposing the explorer to users.

Trace failure remains independent of authorization outcome. The current firewall suppresses sink
exceptions; operational loss metrics and a configurable strict-audit mode remain future work.
