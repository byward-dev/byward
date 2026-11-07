# Contributing to byward

Thanks for helping. This file covers the rules for issues, pull requests and AI-assisted work. The
decisions behind it are in [ADR-0023](docs/adr/0023-project-governance.md).

- Found a vulnerability? Do not open an issue; follow [SECURITY.md](SECURITY.md).
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Read [AGENTS.md](AGENTS.md). It is written for coding agents, and it is also the project's
  **style guide**: layout rules, security rules, commands and branching apply to humans too.
- Domain words are defined in [CONTEXT.md](CONTEXT.md); use them exactly. In particular, the
  **upstream** is always the MCP server, never the identity provider (IdP).
- Design decisions live in [docs/adr/](docs/adr/). A change that contradicts an accepted ADR needs a
  new ADR (or an amendment) in the same pull request.
- Work items are GitHub Issues. For anything bigger than a small fix, comment on the issue (or open
  one) before you write code, so we can agree on the approach.

## Contribution terms

The project is licensed under [Apache-2.0](LICENSE). By its section 5, any contribution you
intentionally submit for inclusion is under the terms of that licence, without extra terms. There is
**no CLA and no DCO sign-off** in v0.1; do not add `Signed-off-by` lines.

Only submit work you have the right to contribute under Apache-2.0.

## Making a change

1. Create a feature branch (in a fork, unless you are a maintainer). Never commit to `main`.
2. Install [mise](https://mise.jdx.dev), then the tools CI's `check` job uses:
   `mise install go golangci-lint go:golang.org/x/tools/cmd/goimports actionlint zizmor shellcheck go:github.com/google/go-licenses/v2`. The `azure-cli` pinned in
   `mise.toml` is an operator tool for Entra setup and real-tenant tests; `mise run check` does not
   need it.
3. Make the change with tests (see [Test policy](#test-policy)).
4. Run `mise run fmt`, then **`mise run check`**, which is exactly what CI runs. Run
   `mise run test:integration` too if you touched integration-tested code (needs Docker).
5. Commit with a [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) message:
   `feat:`, `fix:`, `docs:`, `chore:`, `test:`. Mark breaking changes with `!` or a
   `BREAKING CHANGE:` footer.
6. **Review your own diff** against `origin/main` before asking for review, three ways, and repeat
   each until it finds nothing:
   - **runtime:** run the changed code yourself, including edge cases (empty input, limits, errors);
   - **structure:** check the SOLID structure (one responsibility per type, dependencies on
     interfaces);
   - **tests:** check test quality (behaviour not implementation, names, determinism, coverage of
     the change).

   Coding agents do this with the `/sweep-runtime`, `/sweep-solid` and `/sweep-tests` skills; humans
   without them do the equivalent review by hand. List what each review found and fixed (or "no
   findings") in the pull request.
7. Open a pull request and fill in the template. The PR title is the squash-commit message, so it
   must be a Conventional Commit too.

## Test policy

- **New functionality comes with tests**, and every bug fix comes with a regression test that fails
  without the fix. A pull request without them is not merged unless it explains why a test is not
  possible.
- Tests sit next to the code. Shared fakes (fake IdP, fake upstreams, scripted MCP client) live in
  `internal/testutil/`.
- `mise run check` must pass with no Docker. Docker-based tests run in `mise run test:integration`.
- No wall-clock sleeps in tests; use `testing/synctest` or an injected clock.
- Fixtures use generated identifiers only, never real tenant, user or client IDs, and email addresses
  only at reserved example domains (`example.com`, `example.net`, `example.org`, or any name under
  `.example`). `internal/testutil/fixtures` enforces both in `mise run test` (ADR-0024 §13).
  - In CI, the secret `BYWARD_FORBIDDEN_IDENTIFIERS` lists identifiers and names that must never
    appear in the repository, one per line; every file git would commit (tracked, or untracked and
    not ignored) is checked against it, without regard to case. Findings name only the file and line, never the value.
  - Without the secret (forks, local runs) only email addresses are checked. To check a list
    locally: `BYWARD_FORBIDDEN_IDENTIFIERS="$(cat my-list)" go test ./internal/testutil/fixtures`.
- Fuzz targets (`func Fuzz*`) run their seed corpus in `mise run test`. The nightly `fuzz` workflow
  fuzzes each for 2 minutes (`mise run test:fuzz`; `FUZZTIME=30s` for a shorter local run). It finds
  new targets by itself. When it fails, its `fuzz-crashers` artifact holds the input: unzip it at the
  repository root, which puts the input in its package's `testdata/fuzz/<Target>/`, and fix the code
  until `go test` passes.
- The full strategy (lanes, fuzz targets, budgets) is in
  [ADR-0024](docs/adr/0024-testing-strategy.md).

## Security rules for every change

The proxy sits on the authentication path, so every pull request keeps the invariants in
[docs/quality-lenses.md](docs/quality-lenses.md#invariants). The ones most often at risk:

- never pass an inbound token through to the upstream;
- never log tokens, secrets, authorization codes or PKCE verifiers;
- outbound fetches of client-supplied URLs go through the SSRF guard.

## AI assistance policy

Most commits in this project are written with coding agents (ADR-0002), and AI help is welcome under
these rules:

1. **Disclose it.** Add a `Co-Authored-By` trailer naming the tool or model to each commit it helped
   write, for example `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
2. **A human is accountable.** The person who opens the pull request has read, understands and can
   defend every line of it, and has run `mise run check`. "The AI wrote it" is not an answer in
   review.
3. **Agents never add `Signed-off-by`.** Only a human can certify authorship.
4. **AI-generated security reports must be verified by a human** before they are reported (see
   [SECURITY.md](SECURITY.md)).
5. **Check your tool's terms.** Only use a tool whose terms let you contribute its output under
   Apache-2.0. For example, Anthropic's
   [Commercial Terms](https://www.anthropic.com/legal/commercial-terms) state that the customer
   "owns its Outputs" (checked 2026-11-06).

## Review and merging

- `main` is protected by the `protect-main` ruleset: squash merges only, the `check` status must be
  green and up to date, and there are no bypass actors.
- CODEOWNERS requests a review from the maintainer automatically.
- **Known Scorecard deviation:** the project has one maintainer, who also merges their own pull
  requests, so the OpenSSF Scorecard **Code-Review** check scores zero. Until there is a second
  maintainer, the control is the ruleset plus the required CI check above. This is a recorded decision
  (ADR-0023), not an oversight.

## Versioning and deprecation

The project is in 0.y.z. Configuration keys, the static-clients file, identity-assertion claims, the
audit schema, metric names, log fields, and the image paths and uid are public interface:

- breaking changes only in a minor release, listed under **Breaking Changes** in the release notes;
- a deprecated item keeps working, with a warning, for at least one minor release before it is
  removed.

Releases follow [docs/how-to/release.md](docs/how-to/release.md).
