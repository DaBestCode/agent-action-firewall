# Agent Action Firewall

Agent Action Firewall is a fail-closed authorization gateway for AI-agent actions over MCP and HTTP.
It verifies that a concrete resource operation is backed by valid human authorization, workload
identity, and policy constraints, then records a sanitized decision trace explaining why the action
was allowed or denied.

The project is independent of its authorization engine. Its first engine adapter will target
[Alibaba Open Agent Auth](https://github.com/alibaba/open-agent-auth) at commit
`d75da121a66f8b2ae5be009a98e050fd1dc4c1e6`, but no upstream beta type is exposed by the public API.

## Current status

Days 1–3 foundation:

- Apache-2.0 project and Java 17 Maven structure
- Framework-neutral `AgentAuthorizationEngine`
- Fail-closed `AgentActionFirewall`
- Redacted credential container
- Sanitized trace-sink boundary
- Canonical HTTP and MCP action models with versioned SHA-256 request binding
- Controlled authorization reason taxonomy
- Atomic replay-protection SPI and in-memory implementation
- Initial attack-corpus JSON Schema and wrong-audience case
- Architecture, threat model, upstream pin, and six-week delivery plan

Only `firewall-core` is active today. Gateway, Open Agent Auth adapter, trace persistence, and attack
runner modules will be introduced as their vertical slices become executable.

## Build

Prerequisites:

- Java 17
- Maven 3.9+

```bash
mvn -Dmaven.repo.local=.m2/repository verify
```

The Day 1 build was verified with OpenJDK 17.0.20.1 and Maven 3.9.16. A repository-local Maven cache
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
- [Threat model](docs/threat-model.md)
- [Open Agent Auth pin](docs/upstream-pin.md)
- [Machine-readable upstream lock](upstream/open-agent-auth.lock.json)

## License

Apache License 2.0. See [LICENSE](LICENSE).
