# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — the glossary.
- **`docs/adr/`** — read ADRs that touch the area you're about to work in. ADR-0001 (scope)
  and ADR-0002 (repo structure) apply to almost everything.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The producer skill (`/grill-with-docs`) creates them lazily when terms or decisions actually get resolved.

## File structure

Single-context repo:

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-scope-auth-only-proxy-entra-first-class.md
│   └── 0002-repo-structure-for-agents.md
├── cmd/mcp-authproxy/
└── internal/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

The most common drift is **IdP** vs **upstream**: upstream is always the MCP server, never the IdP.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/grill-with-docs`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0001 (auth-only scope) — but worth reopening because…_
