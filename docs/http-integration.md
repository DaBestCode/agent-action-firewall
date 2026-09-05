# HTTP integration — Day 10

## What runs

`firewall-gateway-http/src/test/java/dev/agentfirewall/gateway/http/WireMockGatewayIT.java`
starts a temporary WireMock container and invokes the real signed-token flow from
`ProtectedServiceTest.verifyFlow`. The Boot resource-server filter and real authorization adapter
run in the test JVM. A **test-only controller** forwards allowed body bytes to the fixed WireMock
address. This is not a production reverse proxy or a containerized gateway deployment.

The flow proves, with generated RSA/EC credentials:

1. A body change is denied without reaching WireMock or consuming the correct proof.
2. The exact authorized body reaches WireMock once and its response returns through Boot.
3. Reuse of the proof is denied without another downstream call.
4. Missing credentials are rejected before the engine.
5. WireMock's journal contains exactly one matching body and no X-Agent, Authorization or Cookie headers.
6. Core traces contain the three engine decisions without token/body content.

WireMock is an intentionally unauthenticated test double. The test checks that the guarded path
does not forward denials; it does not prove that a directly reachable service is protected from
network bypass. Deployment ingress isolation remains mandatory.

## Run and pin

```bash
# Java 17 and the pinned upstream artifacts are required.
# Online first run downloads small test libraries plus test images:
bash scripts/verify-open-agent-auth.sh --containers

# Subsequent cached run:
bash scripts/verify-open-agent-auth.sh --offline --containers
```

The default wrapper runs the normal tests plus MCP tests, without starting containers.
`--containers` adds Maven Failsafe integration-test/verify; Docker absence is a failure, not a skip.
Maven offline mode blocks Maven downloads, not Docker image pulls: pre-cache images for a fully
network-disconnected run. The wrapper still checks the upstream JAR/POM hashes before Maven starts.

Versions verified on 2026-09-04: Java 17.0.20.1, Maven 3.9.16, Docker 29.4.0,
Testcontainers 2.0.5, WireMock 3.13.1. The inspected/pulled WireMock image is locked to:

```text
wiremock/wiremock:3.13.1@sha256:d61e7720f89483fdef5366843b58d1dfd06bcce5828179c9f2f54de5c28354b0
```

The WireMock host port is random and explicitly bound to 127.0.0.1; the test checks Docker's reported
binding. This profile targets a local Docker daemon, not a remote Docker host. No user directory
is mounted into WireMock. Its admin mappings and request journal disappear with the test container.
Testcontainers may start its normal Ryuk cleanup helper with Docker access. A try-with-resources
block stops WireMock and the Boot application; the helper is reaped on JVM exit. Read-only checks
after the run confirmed no remaining WireMock/Ryuk test containers. Downloaded images remain cached.

## Evidence and limits

- [Testcontainers container creation](https://java.testcontainers.org/features/creating_container/)
  documents lifecycle management and versioned image use.
- [Testcontainers 2.0.5 release](https://github.com/testcontainers/testcontainers-java/releases/tag/2.0.5)
  is the selected test library release, not a claim of complete dependency locking.
- [WireMock Docker documentation](https://wiremock.org/docs/standalone/docker/)
  documents the official image and administrative interface.
- Existing upstream constraints and direct source references remain in [HTTP profile](http-profile.md).

Confirmed result: the container test passed with zero skipped tests. This is functional/adversarial
integration coverage, not a penetration test, vulnerability scan, throughput benchmark, TLS test,
network-failure matrix, or evidence that the entire upstream protocol is conformant.
