# ADR-0023: Project governance — 0.y.z with a stability contract, Apache-2.0 §5, disclosed AI help

- Status: Accepted
- Date: 2026-11-06
- Issue: #23 (F22)

## Context

The project has one maintainer, and most commits are written by coding agents (ADR-0002); the licence is
Apache-2.0 (ADR-0002).

Sources:
- **SemVer:** "Major version zero (0.y.z) is for initial development. Anything MAY change at any time."
- **Apache-2.0 §5:** "any Contribution intentionally submitted for inclusion in the Work by You to the
  Licensor shall be under the terms and conditions of this License".
- **AI help:**
  - Linux kernel `coding-assistants.rst`: "AI agents MUST NOT add Signed-off-by tags. Only humans can
    legally certify the Developer Certificate of Origin";
  - kernel `generated-content.rst`: "be transparent about the origin of content", "You are expected to
    understand and to be able to defend everything you submit";
  - the ASF accepts AI help with an optional `Generated-by:` or `Co-authored-by:` trailer, provided
    the tool's terms do not restrict the output;
  - Kubernetes bans AI co-author trailers;
  - curl wants AI-generated reports verified by a human.
- **GitHub private vulnerability reporting:**
  - "anyone can submit"; each report becomes a draft advisory, and CVEs come from GitHub's CNA;
  - it is "separate from" SECURITY.md;
  - admins are notified only when they watch the repository or subscribe to security alerts.
- **OpenSSF:**
  - the Best Practices passing criteria require a published vulnerability process and a test policy;
  - Scorecard's Code-Review check counts an approval "or if the merger is different from the
    committer".
- **Contributor Covenant 3.0** has two placeholders: the reporting contact and the enforcement text.

Comparable Apache-2.0 projects (CONTRIBUTING, 2026-11-06): dex (CNCF) and ToolHive require DCO;
Pomerium and agentgateway have neither DCO nor CLA; oauth2-proxy (MIT) has neither. The `protect-main`
ruleset allows squash merges only, requires the `check` status up to date, and has no bypass actors.

## Decision

1. **Versioning:** 0.y.z with a declared stability contract. Public interface:
   - configuration keys and the static-clients file (ADR-0020);
   - identity-assertion claims (ADR-0016);
   - audit schema, metric names and log fields (ADR-0021);
   - image paths and uid (ADR-0019).

   Breaking changes only in a minor bump, under "Breaking Changes" in the changelog.
2. **Deprecation:** a deprecated item keeps working, with a warning, for at least one minor release,
   then is removed with a changelog entry.
3. **Support:** security fixes for the latest minor only while on 0.y.
4. **Contribution terms:** Apache-2.0 §5; no DCO or CLA in v0.1. DCO may be added later for new
   commits.
5. **AI-assistance policy** (in CONTRIBUTING and AGENTS.md):
   - allowed and disclosed with the `Co-Authored-By` trailer;
   - the human submitter understands, defends and is accountable for the change, and `mise run check`
     passes;
   - AI-generated security reports must be verified by a human;
   - agents never add `Signed-off-by`.
6. **Security:**
   - SECURITY.md plus GitHub private vulnerability reporting;
   - the maintainer subscribes to security alerts;
   - first response within 14 days, reporters credited, CVEs through GitHub's CNA.
7. **Conduct:** Contributor Covenant 3.0 with the suggested enforcement text. The reporting contact is a
   dedicated project alias, never a personal address; it is filled in when the file is written.
8. **Repository hygiene:**
   - CODEOWNERS;
   - issue forms for bugs, features and IdP/client compatibility;
   - a PR template with an ADR and lens checklist;
   - a written test policy and style guide (pointing at AGENTS.md).
9. **Release procedure** written in the repository so that any maintainer can cut a release
   (`mise run release:snapshot`, ADR-0019).
10. **Docs** live in the repository (Diátaxis folders); a docs site is chosen later.

## Consequences

- Scorecard's Code-Review check scores zero while the maintainer merges their own PRs. The deviation is
  documented: the ruleset and the required CI check are the control until there is a second
  maintainer.
- Bus factor is one; the written release procedure and ADRs reduce, not remove, that risk.
- [unverified] whether the AI tool's terms restrict output use, as the ASF condition requires; checked
  when CONTRIBUTING is written.

## Considered options

- DCO now: rejected for v0.1; agents write the commits and must not sign off, and three of five
  comparable projects have no DCO.
- A CLA: rejected; heavy for a solo project and not needed with Apache-2.0 §5.
- Banning AI contributions (Gentoo, NetBSD, QEMU): impossible for an agent-developed project.
