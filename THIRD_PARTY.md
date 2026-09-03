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
