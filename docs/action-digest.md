# Action digest format

Agent Action Firewall binds authorization evidence to a versioned SHA-256 digest of the requested
action. Version 1 uses an unambiguous binary frame rather than delimiter-separated text.

Each field is encoded as:

```text
4-byte unsigned-compatible big-endian byte length || UTF-8 or payload bytes
```

The complete HTTP frame contains, in order:

1. `agent-action-firewall:action:v1`
2. `HTTP`
3. uppercase HTTP method
4. normalized absolute target URI, including its raw query
5. trimmed media type, or an empty field when absent
6. exact HTTP body bytes

The complete MCP frame contains, in order:

1. `agent-action-firewall:action:v1`
2. `MCP`
3. `tools/call`
4. MCP server identifier
5. tool name
6. canonical argument-document bytes

The MCP transport adapter is responsible for producing deterministic argument bytes. Until the
MCP adapter defines and tests JSON Canonicalization Scheme handling, callers must not assume that
semantically equivalent JSON encodings produce the same digest. Different encodings fail safely
with a digest mismatch rather than broadening authorization.

The rendered digest is `sha256:` followed by 64 lowercase hexadecimal characters. Any framing or
normalization change requires a new domain version and new golden test vectors.

The request's policy/trace resource omits the query string even though the digest includes it. This
keeps common URL secrets and sensitive parameters out of trace events. A gateway must extract only
explicitly classified query attributes when a policy needs them.
