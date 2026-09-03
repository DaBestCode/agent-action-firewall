# Open Agent Auth upstream pin

The first adapter targets this exact upstream revision:

| Field | Value |
|---|---|
| Repository | `https://github.com/alibaba/open-agent-auth.git` |
| Commit | `d75da121a66f8b2ae5be009a98e050fd1dc4c1e6` |
| Commit date | 2026-03-15 |
| Upstream artifact version | `0.1.0-beta.1-SNAPSHOT` |
| Java | 17 |
| Spring Boot | 3.3.11 |
| License | Apache-2.0 |

The same revision is recorded in the machine-readable
[`upstream/open-agent-auth.lock.json`](../upstream/open-agent-auth.lock.json). The Week 2 adapter
build consumes that lock rather than a branch or tag. It also verifies the recorded JAR/POM hashes.

The integration builds this exact source revision into an isolated local Maven repository rather
than relying on published SNAPSHOT artifacts. The scripts and repeat-build evidence are described in
[the adapter guide](open-agent-auth-adapter.md). CI automation is not installed yet.

No Open Agent Auth class may appear in the firewall's public API. All translation belongs in the
`firewall-adapter-open-agent-auth` module behind `AgentAuthorizationEngine`. The internal engine has
no public production factory until its trust configuration is reviewed.

Upgrades require:

1. A reviewed commit change in this document and the adapter build configuration.
2. Contract tests for allow, deny, malformed credentials, issuer/audience mismatch, and replay.
3. Attack-corpus regression results.
4. A compatibility note describing changed upstream APIs or authorization semantics.
