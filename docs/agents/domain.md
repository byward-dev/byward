# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — the glossary.
- **`docs/adr/`** — read ADRs that touch the area you're about to work in. ADR-0001 (scope)
  and ADR-0002 (repo structure) apply to almost everything.

## File structure

A single-context repo: one `CONTEXT.md` at the root, and the ADRs in `docs/adr/`, listed with their
amendments in [docs/adr/README.md](../adr/README.md).

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

The most common drift is **IdP** vs **upstream**: upstream is always the MCP server, never the IdP.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/grill-with-docs`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0001 (auth-only scope) — but worth reopening because…_
