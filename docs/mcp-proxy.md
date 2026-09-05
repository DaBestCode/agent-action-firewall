# MCP authorization proxy — Day 12

`McpAuthorizationProxy` is a transport-neutral authorize-before-forward coordinator. It accepts an
administrator-configured server ID, one raw JSON-RPC tools/call envelope and `PresentedCredentials`.
It canonicalizes first, creates a server-timestamped/request-ID `AgentActionRequest`, calls the core
firewall exactly once, and forwards only `CanonicalToolCall.forwardingBytes()` after allowance.

`McpForwarder` deliberately receives only server ID and canonical bytes. There is no credentials,
header, session or arbitrary destination parameter in that interface. Implementations must map the
server ID through trusted configuration and enforce connection/time/response deadlines. The proxy
bounds a nonempty downstream response at 1 MiB but otherwise treats it as opaque untrusted data.
It does not validate JSON-RPC response IDs, content or tool output. An MCP SDK/network adapter remains
required before deployment.

Malformed requests never call the engine or downstream and receive a generic JSON-RPC `-32600`
response with null ID. Authorization denial returns `-32001`; downstream exception/null/empty/oversize
returns `-32002`. Known-request errors retain only the already-canonical string/integer correlation
ID. Parser, engine and forwarder exception messages are not exposed. `McpProxyResult` defensively
copies response bytes and redacts them from `toString`; its decision ID is safe trace correlation.

Important limitations:

- This proxy can enforce any core engine, but the current signed Open Agent Auth HTTP profile rejects
  MCP actions. Tests use a controlled engine; real MCP credential validation is not yet implemented.
- JSON-RPC IDs are correlation only and excluded from action scope. They do not replace token JTIs or replay.
- A successful authorization is traced before the downstream call. A later downstream failure is a
  transport result, not a second authorization decision; no transport-failure trace schema exists yet.
- Pre-canonicalization malformed attempts are not core traces because no safe action exists yet.
- Credentials remain in caller memory; this class only prevents their forwarding through its API.

`McpAuthorizationProxyTest` proves exact canonical forwarding, denial/engine-failure isolation,
malformed-input isolation, response bounds, defensive copies, trace sanitization and generic errors.
The pinned upstream already has a separate HTTP-oriented
[MCP interceptor](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/open-agent-auth-mcp-adapter/src/main/java/com/alibaba/openagentauth/mcp/server/McpAuthInterceptor.java).
This downstream proxy is not presented as a missing upstream contribution. Maintainer intent remains unclear.
