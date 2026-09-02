# Agent Action Firewall

Agent Action Firewall is an independent project building a fail-closed authorization gateway for
AI-agent actions over MCP and HTTP. Its intended gateway will verify human authorization, workload
identity and policy constraints, then record a data-minimized decision trace. The current milestone
is a tested core and test kit, not a deployed or cryptographically complete gateway.

The project is independent of its authorization engine. Its first engine adapter will target
[Alibaba Open Agent Auth](https://github.com/alibaba/open-agent-auth) at commit
`d75da121a66f8b2ae5be009a98e050fd1dc4c1e6`, but no upstream beta type is exposed by the public API.

## Current status

Days 1–5 foundation:

- Apache-2.0 project and Java 17 Maven structure
- Framework-neutral `AgentAuthorizationEngine`
- Fail-closed `AgentActionFirewall`
- Redacted credential container
- Sanitized trace-sink boundary
- Canonical HTTP and MCP action models with versioned SHA-256 request binding
- Controlled authorization reason taxonomy
- Atomic replay-protection SPI and in-memory implementation
- Versioned, bounded in-memory trace storage with filtering and receipt-time retention
- Reusable authorization-engine contract tests and an explicitly test-only deterministic engine
- Initial attack-corpus JSON Schema and wrong-audience case
- Architecture, threat model, upstream pin, and six-week delivery plan

`firewall-core` and `firewall-testkit` are active today. Gateway, Open Agent Auth adapter, durable trace
persistence, and attack runner modules will be introduced as their vertical slices become executable.
Use `firewall-testkit` only with test scope; it does not verify real credentials.

## Build

Prerequisites:

- Java 17
- Maven 3.9+

```bash
mvn -Dmaven.repo.local=.m2/repository verify
```

The current build was verified with OpenJDK 17.0.20.1 and Maven 3.9.16. A repository-local Maven cache
keeps build artifacts out of the user profile. See [ROADMAP.md](ROADMAP.md) for the delivery sequence.

## Design principles

- Fail closed when authorization cannot be established.
- Never log or trace raw authorization credentials.
- Bind authorization to a canonical operation digest.
- Keep transports and authorization engines replaceable.
- Treat LLM output and tool parameters as untrusted input.
- Test security claims with adversarial fixtures, not placeholder assertions.

## Documentation

- [Delivery roadmap](ROADMAP.md)
- [Architecture](docs/architecture.md)
- [Action digest format](docs/action-digest.md)
- [Trace storage and sanitization limits](docs/trace-storage.md)
- [Engine test kit](docs/engine-testkit.md)
- [Week 1 API decisions and limitations](docs/decisions/0001-week-one-boundaries.md)
- [Threat model](docs/threat-model.md)
- [Open Agent Auth pin](docs/upstream-pin.md)
- [Machine-readable upstream lock](upstream/open-agent-auth.lock.json)

## License

Apache License 2.0. See [LICENSE](LICENSE).
