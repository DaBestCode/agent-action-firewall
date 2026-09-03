# Architecture

Agent Action Firewall is an enforcement boundary for MCP and HTTP agent actions. The project is
organized as a hexagonal application so transport, authorization implementation, trace storage,
and replay storage can evolve independently.

```text
MCP / HTTP adapter
       |
       v
AgentActionRequest ----> AgentActionFirewall ----> AgentAuthorizationEngine
                                |                         |
                                v                         v
                      AuthorizationTraceSink      Open Agent Auth adapter
                                |
                                v
                       sanitized trace store
```

## Dependency rule

Dependencies point inward. `firewall-core` has no Spring, MCP, persistence, JSON, or Open Agent Auth
dependency. Transport and vendor adapters depend on the core contract; the core never imports them.

## Initial modules

- `firewall-core`: request and decision models, authorization engine SPI, fail-closed orchestration.
- `firewall-testkit`: reusable JUnit adapter contract and test-only deterministic engine. Never a runtime dependency.
- `firewall-adapter-open-agent-auth`: pinned, opt-in internal translation to Open Agent Auth. Production configuration pending.
- `firewall-gateway`: Spring Boot HTTP/MCP enforcement. Planned for Week 2.
- `firewall-trace-store`: sanitized trace persistence and queries. Planned for Week 3.
- `firewall-attack-runner`: attack-corpus execution. Planned for Week 4.

## Security invariants

1. Failure to establish authorization results in denial.
2. Raw credentials never enter traces, metrics, exception messages, or model `toString()` output.
3. Trace-store failure does not turn denial into allowance or allowance into denial.
4. Every request carries a digest of the canonical operation that was authorized.
5. Vendor-specific types remain behind `AgentAuthorizationEngine`.
6. A delegated operation must never be broader than its parent authorization.

The core also owns the action-digest format and replay-protection SPI. See
[`action-digest.md`](action-digest.md) for the byte-level interoperability contract.

The bounded in-memory trace repository lives in core; durable trace persistence remains an adapter.
See [trace storage](trace-storage.md), [test-kit usage](engine-testkit.md), and the
[Week 1 review](decisions/0001-week-one-boundaries.md) for limitations and integration obligations.
