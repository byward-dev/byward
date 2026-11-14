## What and why

<!-- What does this change, and why? Link the issue: "Closes #123". -->

## Checklist

- [ ] The PR title is a Conventional Commit (`feat:`, `fix:`, `docs:`, `chore:`, `test:`); breaking changes are marked
- [ ] `mise run check` passes (and `mise run test:integration` if integration-tested code changed)
- [ ] New behaviour has tests next to the code; a bug fix has a regression test
- [ ] Domain words follow `CONTEXT.md` (the upstream is the MCP server, never the IdP)

### Decisions (ADRs)

- [ ] I read the ADRs in `docs/adr/` that this change touches: <!-- e.g. ADR-0014 -->
- [ ] The change follows them, **or** this PR adds or amends an ADR

### Quality lenses (`docs/quality-lenses.md`)

- [ ] I walked the lenses this change touches, per the feature × lens map: <!-- e.g. #secure, #operable -->
- [ ] Every invariant in `docs/security-posture.md` still holds; most often at risk: no token passthrough; no tokens, secrets, codes or verifiers logged; client-supplied URLs go through the SSRF guard
- [ ] Public interface (config keys, assertion claims, audit schema, metrics, log fields, image paths) is unchanged, **or** the change is listed as breaking or deprecated
- [ ] Docs are updated for anything an operator, user or upstream author sees

### Sweeps (on the diff against `origin/main`; the tier and rounds are in AGENTS.md)

- [ ] Runtime: changed code run directly, including edge cases (`/sweep-runtime`)
- [ ] SOLID structure (`/sweep-solid`)
- [ ] Test quality (`/sweep-tests`)

Findings and fixes per sweep (or "no findings"):

### AI assistance

- [ ] AI help is disclosed with `Co-Authored-By` trailers, and I understand and can defend every line (CONTRIBUTING.md)
