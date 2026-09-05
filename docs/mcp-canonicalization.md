# MCP tools/call canonicalization — Day 11

## Boundary

`firewall-protocol-mcp` adds `McpCallCanonicalizer.canonicalize(serverId, requestBytes)`.
The server ID must come from administrator routing configuration, never a model-selected URL.
The result pairs an immutable core `McpToolAction` with defensive-copy `forwardingBytes()`.
An eventual interceptor must authorize that action and forward **those bytes**, not reparse or
rebuild a different request after authorization. `CanonicalToolCall.toString()` is redacted and
rejections use a fixed message without parser causes or payload excerpts.

Canonicalization itself does not execute tools, verify credentials, manage MCP sessions or provide
replay protection. Day 12 adds a transport-neutral [authorization proxy](mcp-proxy.md), but the HTTP
authorization profile still rejects MCP actions and no network/MCP SDK adapter exists. The existing
raw-byte `McpToolAction` constructor does not validate JSON.

## aaf-mcp-json-v1

This is a deliberately constrained JSON profile, **not full RFC 8785 JCS** and not a general MCP SDK.
It accepts one JSON-RPC 2.0 `tools/call` request with exactly `jsonrpc`, `id`, `method`, `params`.
Params contain `name` and optional `arguments`; omitted arguments become `{}`. Arguments must be
an object. Request IDs are nonblank strings up to 256 UTF-16 units or safe integers, never null.
Tool and configured server names match `[A-Za-z0-9_.-]{1,128}`. Batch requests, notifications,
other methods, extra envelope fields, `_meta`, and extension params are rejected, not discarded.

Canonical representation:

- UTF-8 only, no malformed encodings or lone surrogates. Unicode normalization is never applied.
- Object keys sort recursively by unsigned UTF-16 code units; arrays retain order.
- No insignificant whitespace. Strings use JSON escapes for quotes, backslashes and control
  characters, lowercase hexadecimal escapes where needed, and literal Unicode otherwise.
- Numbers must have an exact integral value between -9007199254740991 and 9007199254740991.
  Equivalent spellings such as `1`, `1.0`, `1e0` become `1`; negative zero becomes `0`.
  Fractions and larger numbers reject: represent precise decimal amounts as schema-defined strings.
  There is no binary-floating-point rounding of input numbers.
- Duplicate decoded property names reject at every depth, including escaped-name collisions.
  Comments, NaN, infinity, leading zeros, trailing commas and additional JSON documents reject.

Resource bounds: 65,536 input bytes; 65,536 output bytes for either argument document or forwarded
request; depth 32 including the envelope; 16,384 UTF-16 units per string; 1,024 per property name;
128 characters per numeric token; absolute decimal scale at most 1,000; 10,000 total JSON values
including containers. These bounds apply before forwarding. The output-size bound also catches
short exponent notation expanding into many integer digits. No global Jackson defaults are changed.

Why constrain numbers: RFC 8785 specifies ECMAScript-compatible number serialization. Implementing
only Java's default floating-point output would not establish that compatibility. The chosen subset
avoids silent rounding and makes the accepted representation testable. Expanding numeric support
requires a reviewed profile revision and interoperability tests.

## Digest and golden vector

The core action:v2 frame already binds protocol, server ID, tool name and canonical argument bytes.
MCP JSON-RPC `id` is correlation metadata, not authorization scope: changing it changes forwarding
bytes, not the action digest. It must not substitute for a cryptographically bound replay nonce.
No existing HTTP digest behavior changes.

For server `inventory`, tool `buy`, and input arguments `{"sku":"A-1","quantity":2.0}`:

```text
canonical arguments: {"quantity":2,"sku":"A-1"}
digest: sha256:96aee381e7ed8f5222fe93c559b22bcb747c0b1902537caedc94c012d2f5cf7b
```

The fixed test expectation was independently calculated using Node's SHA-256 with the documented
four-byte big-endian length prefixes, not copied from the Java method under test.
`McpCallCanonicalizerTest` checks this vector, representation equivalence, changed actions,
forwarding idempotence, defensive copies, UTF-16 sorting, numeric/Unicode rejection, bounds and concurrency.

## Build and evidence

```bash
# Independent of Spring/Open Agent Auth; uses an ordinary Maven cache:
mvn -Pmcp -Dmaven.repo.local=.m2/repository verify

# Or verify alongside the pinned HTTP adapter using its existing cache:
bash scripts/verify-open-agent-auth.sh --offline
```

Primary references:

- [MCP 2025-06-18 tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
  defines tools/call and its name/arguments fields. This project intentionally supports a narrower subset.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) describes duplicate-name, Unicode, sorting and
  number-serialization requirements. Our integer-only profile does not claim full JCS compliance.
- The pinned upstream already has an [MCP authentication interceptor](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-mcp-adapter/src/main/java/com/alibaba/openagentauth/mcp/server/McpAuthInterceptor.java).
  Its inspected source maps HTTP headers/body into `ResourceRequest` for validation; this independent
  canonicalization module is not presented as an upstream feature proposal or a replacement for that module.

On 2026-09-04 the read-only GitHub history refresh included all five issues and nineteen PRs,
including closed [issue #14](https://github.com/alibaba/open-agent-auth/issues/14), closed predecessor
[PR #19](https://github.com/alibaba/open-agent-auth/pull/19), and merged
[PR #20](https://github.com/alibaba/open-agent-auth/pull/20). Upstream conformance tests already exist.
These listings and the earlier discussion review do not establish maintainer endorsement of this
downstream profile; maintainer intent remains unclear. No upstream comments, issues or PRs were created.
