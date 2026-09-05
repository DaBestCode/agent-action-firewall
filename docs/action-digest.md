# Action digest format

Agent Action Firewall binds authorization evidence to a versioned SHA-256 digest of the requested
action. Version 2 uses an unambiguous binary frame rather than delimiter-separated text.

Each field is encoded as:

```text
4-byte unsigned-compatible big-endian byte length || UTF-8 or payload bytes
```

The complete HTTP frame contains, in order:

1. `agent-action-firewall:action:v2`
2. `HTTP`
3. exact HTTP method token (case preserved)
4. normalized absolute target URI, including its raw query
5. trimmed media type, or an empty field when absent
6. exact HTTP body bytes

The complete MCP frame contains, in order:

1. `agent-action-firewall:action:v2`
2. `MCP`
3. `tools/call`
4. MCP server identifier
5. tool name
6. canonical argument-document bytes

The MCP protocol adapter now defines [aaf-mcp-json-v1](mcp-canonicalization.md), a bounded safe-integer
JSON subset. Use its `McpCallCanonicalizer` to produce deterministic argument bytes and the matching
request to forward. It is not full RFC 8785 JCS. The raw-byte `McpToolAction` constructor remains for
compatibility but does not validate canonical JSON; it is not an untrusted-input boundary.
MCP authorization and transport forwarding are still planned. The digest algorithm remains action:v2:
canonicalization fills its existing argument-bytes field; no framing or HTTP behavior changes.

The rendered digest is `sha256:` followed by 64 lowercase hexadecimal characters. Any framing or
normalization change requires a new domain version and new golden test vectors.

Version 2 replaces v1 after the Week 1 review: raw paths (including repeated slashes, dot segments and
percent encoding) and method case are preserved. Scheme/host case, default ports and empty paths are
still normalized; IPv6 brackets are retained exactly once. There is no v1 fallback. Gateways must
authorize the representation they actually forward, with no subsequent semantic transformation.

The request's policy/trace resource omits the query string even though the digest includes it. This
keeps common URL secrets and sensitive parameters out of trace events. A gateway must extract only
explicitly classified query attributes when a policy needs them.
