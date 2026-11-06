# Security policy

mcp-authproxy is an authentication proxy, so we treat security reports as the highest-priority work
in the project.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/corker/mcp-authproxy/security/advisories/new)
(repository **Security** tab → **Report a vulnerability**). Anyone with a GitHub account can submit a
report; it opens a draft security advisory that only you and the maintainers can see.

Please include:

- the version or commit, and how it is deployed (IdP, upstream kind, client);
- the steps to reproduce, and what an attacker gains;
- whether you found it with an AI tool. AI-generated reports are welcome only after a human has
  reproduced and verified the finding; unverified reports may be closed without further reply.

Never include real tokens, secrets, authorization codes or tenant identifiers. Use test values.

## What happens next

| Step | Target |
|---|---|
| First response | within **14 days** |
| Assessment and severity agreed with you | as soon as we can reproduce it |
| Fix and advisory published | release date coordinated with you |

- We fix the issue in a private fork attached to the advisory, then publish the advisory together with
  the release that contains the fix.
- **CVE IDs** are requested through GitHub, which is a CVE Numbering Authority (CNA).
- **Reporters are credited** in the advisory, unless you ask not to be.

## Supported versions

The project is in initial development (0.y.z). Security fixes go into the **latest minor release
only**; upgrade to it to get a fix. Older minors get no backports.

| Version | Supported |
|---|---|
| latest `0.y` minor | yes |
| older `0.y` minors | no |

## Scope

In scope: this repository's code, its release artifacts (binaries, container image), and the
documented default configuration.

Out of scope: vulnerabilities in the MCP server behind the proxy (the upstream), the identity
provider (IdP), or the MCP client; report those to their maintainers. Issues that need a
misconfiguration the documentation warns against are welcome as hardening suggestions in a normal
issue.
