# ADR-0031: Setting shapes: display and refusal

- Status: Accepted
- Date: 2026-11-19
- Issue: #492 (tracker #485); amends ADR-0020 §4 and §6

## Context

ADR-0020 §4 makes one registry drive validation and redaction, and §6 logs the effective
configuration with secrets as `<redacted>`. On `main`, redaction of a setting that is not secret is
decided in two ways. The registry's `Secret`, `URL`, `URLs` and `Command` booleans pick how an
accepted value is displayed. A refused value goes through `logging.Quote`, which guesses from the
text (`://`, `:/`, `;`, `@`, `?`, `#`), or through a plain `%q`.

Measured on `main` with the real binary (#485):

- **Refused values leak.** A matrix fed 14 secret-shaped values into every non-secret setting
  through `check --offline` (main 0116cf29). 45 of the 66 non-secret settings printed a refused value
  whole, in 478 of 924 cells. Most went through `%q`, not `Quote`: the booleans, enums, durations,
  numbers, the Entra tenant, the rate limits, `assertion-claims` and the access gate's lists. `Quote`
  misses every shape it has no rule for (#478).
- **Accepted values can be secrets.** A second matrix gave 46 text settings 13 secret formats
  (main 7bacc2b0):
  - 12 settings accept and print every format.
  - 6 are refused only at wiring, after `--print-config` and the startup log have printed the value:
    `entra-client-id`, the four gate lists and `app-client-ids`.
  - A UUID-shaped secret passes every GUID check.
  - A JWT is a valid dotted host name.
- **The stdio `PATH`.** A `PATH` from the secret `upstream-env` setting reached an error. That leak
  was fixed ahead of this design (#483).

Prior art. Each item was read from source at the version given.

| Project | Mechanism | What it shows |
|---|---|---|
| oauth2-proxy v7.15.6 | Each message is written to leave secrets out. | A refused URL whole, user information included: `"error parsing %s-url=%q %s"` ([`pkg/validation/options.go` L184-189](https://github.com/oauth2-proxy/oauth2-proxy/blob/v7.15.6/pkg/validation/options.go#L184-L189)). |
| Traefik v3.7.19 | The message leaves the value out. | A malformed `user:hash` entry is refused without the entry: "The user is not part of the error, as it may come from a secret" ([`pkg/middlewares/auth/basic_auth.go` L157](https://github.com/traefik/traefik/blob/v3.7.19/pkg/middlewares/auth/basic_auth.go#L157)). |
| OpenTelemetry Collector `configopaque` v0.165.0 | By type: `String`, `GoString`, `MarshalText` and `MarshalBinary` return `[REDACTED]`. | The text only through a cast to `string` ([`config/configopaque/opaque.go`](https://github.com/open-telemetry/opentelemetry-collector/blob/v0.165.0/config/configopaque/opaque.go)). |
| prometheus/common v0.74.0 | By type: `Secret` marshals to YAML and JSON as `<secret>`. | `Secret` has no `String()` method, so `%s` prints it ([`config/secret/secret.go`](https://github.com/prometheus/common/blob/v0.74.0/config/secret/secret.go)). |
| CockroachDB v26.2.12 | Typed constructors (`RegisterStringSetting`) take options. `Sensitive` makes a string setting "always be redacted in any output"; `WithValidateString` adds a check. | Only a `Sensitive` string setting is always redacted ([`pkg/settings/options.go` L86-91](https://github.com/cockroachdb/cockroach/blob/v26.2.12/pkg/settings/options.go#L86-L91), [`pkg/settings/string.go` L119-121](https://github.com/cockroachdb/cockroach/blob/v26.2.12/pkg/settings/string.go#L119-L121)). |

The projects that redact decide by the declared type or option, never from the value's text. None
of them redacts a value that is refused.

## Decision

### 1. A value refused for its form is never printed

- **The rule.** A value is refused for its form when it does not parse: it is not a GUID, not a
  host, not one of the words an enum allows. Such a value is not shown, in part or whole, whatever
  its length or grammar. This includes a short closed-grammar value such as an enum, a boolean or a
  duration.
- **What the refusal says.** Every refusal has the same fields:
  - the setting;
  - the entry's position, for a list ("entry 2 of 3");
  - the value's length;
  - a reason from the parser, which every refusal must have;
  - an example of the right form;
  - for an IdP identifier, where to find it, such as "Entra admin center, Overview, Tenant ID".

  Every message uses one format: `BYWARD_X: want …; got …`.
- **Meaning.** A value refused for its meaning (not loopback, out of range, reserved) parsed, so it
  is shown as the parser read it, not as it was given.
- **Mechanism.** Every setting's text is held in an opaque type, as the OpenTelemetry Collector's
  `configopaque` does.
  - `String`, `GoString`, `Format`, `LogValue`, `MarshalJSON` and `MarshalText` print a redacted form.
    slog's JSON handler never calls `String()`; it prefers `LogValue`, then `MarshalJSON`, then
    `MarshalText` (probed on Go 1.27).
  - The raw text is reachable only through `.Raw()`, which only parse functions call; a test fails on
    any other caller.
  - A parser turns a standard-library error that repeats its input, such as `*url.Error`, into a fixed
    reason chosen by the error's type. Even the error that `errors.Unwrap` returns can quote part of
    the value: `invalid port ":…" after host`.
- **Acceptance.** A permanent leak test feeds canary values in 14 secret shapes into every setting. It
  runs them through startup, `check --offline`, `--print-config` and `doctor`, in the text and JSON
  log formats, and fails if a canary appears.

### 2. Accepted values that look like secrets

- **Checks move into config.** The access gate's entry checks (the four gate lists and
  `app-client-ids`) and the Entra client ID's GUID check move from wiring into config. They then run
  before anything is printed, as the client-denylist and issuer checks already do.
- **Documented token prefixes.** A closed list of vendor-documented token prefixes is refused by
  class, with obvious kinds of mistake, such as a connection string or a domain where a GUID belongs.
  - Examples of prefixes: `ghp_`, `github_pat_`, `xoxb-` and the JWT's `eyJ`.
  - A match is refused by naming its class only: "this looks like a GitHub token".
  - The list holds only formats a vendor documents. None of them appears in any value in this
    repository's docs, tests or deploy files.
- **One cap.** An Entra app role value is at most 120 characters. The Microsoft Graph
  [appRole resource](https://learn.microsoft.com/en-us/graph/api/resources/approle) says it "Must not
  exceed 120 characters in length". No other shape gets a length cap, because no other limit is
  documented: RFC 9110 §5.1, RFC 6749 §3.3, OIDC Core §5.1.2, and the role names of Okta, Auth0 and
  Keycloak set none.
- **What is left.** A secret with no documented prefix can still appear in `--print-config` and the
  startup log if it is pasted into a free-text setting that never leaves the host. Such settings are
  claim names, role names, `upstream-strip-headers` and a single-label host. A single-label host
  can't be refused: [Harden a deployment](../how-to/harden-a-deployment.md) documents internal service
  names. This goes in the security posture's known gaps.

### 3. Every setting declares a shape (option B′)

Each registry entry carries a *shape*: how its accepted value is displayed and how a refused value is
reported.

1. A shape's fields are unexported. The only constructor, `newShape(display, refused)`, panics at
   init when given a nil function, so a half-built shape can't reach a request.
2. Every setting has a shape. No list of unshaped settings has to be kept in step.
3. Shapes replace the `Secret`, `URL`, `URLs` and `Command` booleans. `Bool` stays, because it is a
   parse rule, not a display rule.
4. The parser hands its setting's shape to the refusal. Nothing looks up a setting by name from a
   global.
5. A URL refusal reuses the parsed result instead of parsing again. Whether a value is opaque
   follows from its shape, not from a second list.

Example: the display rule from ADR-0020 §6's amendment of 2026-11-17 (#458) is two shapes.

- **The URL shape.** A URL setting is shown by its scheme, host and path. `;…`, `?…` or `#…` marks
  where path parameters, a query or a fragment are left out, because these can hold an API key.
- **The command shape.** The stdio upstream's command is shown by its program and how many
  arguments follow, because an argument can be a token.

The proxy uses both values whole.

### 4. Where the rule is written down

- **Security invariant 2 keeps its wording.** Its configuration part becomes one rule: a setting's
  value reaches a log, an error, `--print-config` or doctor only through its setting's shape, and a
  value refused for its form is never printed.
  - Its "Enforced in" and "Tested by" cells will point at the shapes and the leak test, replacing
    today's list of special cases.
  - Redaction outside configuration stays under invariant 2 as it is: the logging allowlist, URL
    and body errors, the stdio env and OTel.
- **The invariant and the known gaps change with the code.** They change in the PRs that build the
  shapes, so `docs/security-posture.md` never describes code that is not on `main`.

## Consequences

- `logging.Quote` and its heuristics are deleted. `logging` keeps `URL`, `MarkedURL`, `Hidden` and
  the error helpers.
- **Operators lose some information.** A refused `ftp://up.example/x` reads "its scheme is not http
  or https (18 characters, not shown)" instead of echoing the URL. Each refusal's required reason and
  example stand in for the echo. In a blind walkthrough, 10 broken configurations were fixed from the
  proposed messages alone, 10 of 10. The one guess came from a message without a reason.
- **Messages change for most settings**, and the tests that pin them change too. The spike's rate,
  about 75 expectation lines for 4 to 6 settings, suggests 400 to 700 lines in all.
- **A new setting costs a shape.** A registry test fails on a setting without one; `newShape` fails at
  init on a half-built one.
- **Delivery.** The work lands in four PRs, merged in order: this ADR (#492); every setting has a shape
  and display goes only through it (#493); refusals through the shape, with the opaque type and the
  invariant 2 rewrite (#494); the config checks, the prefix recognizer, the role cap and the known
  gaps (#495). The rule for which hosts are accepted (#486) is written as a shape after #493.

## Considered options

- **Keep `logging.Quote` and add rules to it** (#478): rejected. It guesses from the text, and every
  shape without a rule leaks. The measured leaks are mostly in values it never sees.
- **Show a short refused value from a closed grammar** (an enum, a boolean, a duration): rejected.
  A pasted secret is refused there like any typo, and the reason plus the example give the
  operator what the echo did.
- **Keep the gate and Entra client ID checks at wiring, and have them report the position and the
  reason:** rejected. The value would still be printed by `--print-config` and the startup log before
  wiring refuses it.
- **Cap the length of every identifier:** rejected. No standard or IdP documents a limit, apart from
  the Entra app role value.
- **A: a shape as methods on a value type**, an enum with one `switch` per rule. **B: a shape as
  functions in the registry.** The spike built both for 6 settings and changed each in 4 ways.
  Reviewing them angle by angle: single responsibility B, open/closed B, Liskov A, interface
  segregation A, dependency inversion B.
  - Chosen: **B′**, which is B with the five changes in decision 3.
  - Changes 1 and 2 answer the Liskov finding: a nil function panicked at its first use, at a request.
  - Change 1 answers the interface segregation finding: exported fields widened the surface.
