# Third-party components

Agent Action Firewall is an independent Apache-2.0 project and is not an Alibaba product.

The optional Open Agent Auth adapter uses
[Alibaba Open Agent Auth](https://github.com/alibaba/open-agent-auth) at the commit recorded in
[the upstream lock](upstream/open-agent-auth.lock.json). Its source is licensed under
[Apache License 2.0](https://github.com/alibaba/open-agent-auth/blob/d75da121a66f8b2ae5be009a98e050fd1dc4c1e6/LICENSE).
The build retains upstream source headers and builds the unmodified core in an ignored local folder.

No upstream source or binaries are committed into this repository. Distribution packaging must
preserve applicable third-party licenses/notices for bundled dependencies; the dependency SBOM and
distribution review remain part of the release milestone.

The optional HTTP gateway uses Spring Boot 3.3.11 and its managed dependencies, matching the pinned
upstream baseline for this compatibility experiment. Nimbus JOSE JWT supplies cryptographic
verification inside the adapter. These are Maven dependencies, not copied source. This version
selection is not a current vulnerability assessment; dependency/security updates must precede release.

Day 10 adds test-only Testcontainers Java 2.0.5 (MIT) and the WireMock 3.13.1 Docker image
(Apache-2.0), pinned by manifest digest in `WireMockGatewayIT`. Testcontainers' cleanup helper is
managed by its versioned library; the WireMock pin does not claim to lock every helper image.
Day 11 uses Jackson Core 2.17.3 (Apache-2.0) for bounded JSON parsing, matching the existing cache.
Canonicalization/serialization code in this repository is original and covers only its documented
safe-integer profile, not the complete RFC 8785 algorithm.

Day 13 uses pgJDBC 42.7.13 (BSD-2-Clause) and a test-only official PostgreSQL 17.11 Alpine image
(PostgreSQL License), pinned by manifest digest. The selected driver includes the security fixes
documented for 42.7.11 and 42.7.12; this does not replace a dependency scan or TLS configuration review.
