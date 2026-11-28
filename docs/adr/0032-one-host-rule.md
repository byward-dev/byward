# ADR-0032: One host rule

- Status: Accepted; amended 2026-11-21 (#521), 2026-11-26 (#524), 2026-11-26 (#644), 2026-11-26 (#656)
- Date: 2026-11-19
- Issue: #520 (tracker #486); amends ADR-0018 §1–2, ADR-0020 §4 and ADR-0008 §4, §8–9

## Context

byward reads a host in many settings and two request headers, and on `main` (0116cf29, before #481)
it does so with four separate rules:

1. **The browser-IP rule:** `browserIPv4`, `browserHost`, `CanonicalHost`.
2. **The name-syntax rule:** `validHostName`, `hostNameReason`, `asciiHost`.
3. **The IDNA fold:** `registration.BrowserHost`, `BrowserHostOK`, `transitionalHost`.
4. **The loopback test**, in three copies: `config.isLoopback`, `oidc.loopback` and
   `registration.loopbackHosts`.

Each setting combines them in its own way, so a fix to one setting leaves its neighbours behind. Run
against the real code, one spelling gets different answers:

- **Numeric IPv4.** `BYWARD_ALLOWED_HOSTS` rewrites `010.0.0.1` to `8.0.0.1`. `BYWARD_ALLOWED_ORIGINS`
  and the public URL refuse it. The CIMD lists keep `127.1` as written.
- **A name ending in a number** (`mcp.10`, `10.0.0.999`) is accepted by the allowed hosts and the CIMD
  lists, and refused by the public URL, the origins and the client denylist.
- **IPv6.** The public URL refuses a form that is not the shortest; the allowed hosts and the origins
  rewrite it silently.
- **A trailing dot** is refused in every setting except the client denylist, which strips it. At
  request time the denylist folds it but the CIMD trust check does not (#486).
- **Loopback.** None of the three copies folds case, so `LOCALHOST` is not loopback for the `--dev`
  OIDC issuer or the no-auth listen address (#482).
- **Default port.** `BYWARD_PUBLIC_URL=https://mcp.example.com:443/mcp` loads, and byward publishes
  the issuer and resource with `:443` (#484).
- **Characters.** Go's `url.Parse` accepts RFC 3986 reg-name characters in a host. So
  `S3CRET~tok` parses as a valid host, and a pasted secret is shown as one (the #485 spike).

**What the standards say.** The WHATWG URL Standard (Living Standard, "Last Updated 14 November 2026",
<https://url.spec.whatwg.org/>) is what browsers implement:

- **§3.2:** a forbidden host code point is "U+0000 NULL, U+0009 TAB, U+000A LF, U+000D CR, U+0020
  SPACE, U+0023 (#), U+002F (/), U+003A (:), U+003C (<), U+003E (>), U+003F (?), U+0040 (@), U+005B
  ([), U+005C (\), U+005D (]), U+005E (^), or U+007C (|)". A forbidden domain code point is "a
  forbidden host code point, a C0 control, U+0025 (%), or U+007F DELETE." So `_`, `~` and `$` are
  allowed in a domain.
- **§3.3:** "If domain is an ASCII string, then set result to domain, lowercased." A non-ASCII name
  goes through UTS 46 with "CheckHyphens set to beStrict, CheckBidi set to true, CheckJoiners set to
  true, UseSTD3ASCIIRules set to beStrict, Transitional_Processing set to false, VerifyDnsLength set to
  beStrict, and IgnoreInvalidPunycode set to false."
- **§3.5:** a host whose last label is a number goes to the IPv4 parser, which reads hex `0x`, a
  leading `0` as octal and fewer than four parts. So `127.1` is `127.0.0.1`.
- **§3.1:** "The example.com and example.com. domains are not equivalent and typically treated as
  distinct." "Support for <zone_id> is intentionally omitted."
- **§4.4, the port state:** "Set url's port to null, if port is url's scheme's default port;
  otherwise to port." The quote is verbatim; the step number within the port state was not read.

What browsers actually do was checked with Node 22's WHATWG `URL` (run 2026-11-19, #486 Q3):

- `https://h.example:443/mcp` gives href `https://h.example/mcp`, host `h.example` and origin
  `https://h.example`. `http://localhost:80/mcp` drops `:80` the same way; `:8443` is kept.
- `https://my_host.example/mcp`, `https://my_mcp:8000/mcp` and `https://S3CRET~tok/mcp` all parse.

The identifiers an IdP or a client compares are compared exactly:

- **Redirect URIs:** RFC 6749 §3.1.2.3 "simple string comparison"; RFC 9700 §4.1.3 "exact string
  matching". The one exception is a loopback port (RFC 8252 §7.3).
- **The issuer:** RFC 8414 §3.3 "identical", §4 "code-point-to-code-point equality"; OpenID
  Connect Discovery 1.0 §4.3 "MUST be identical".
- **The resource:** RFC 9728 §3.3 says it "MUST be identical to the URL that the client used to
  make the request".

**Underscores.** A host on an internal network may hold `_`:

- **Compose service names.** The Compose Specification's schema allows service names matching
  `^[a-zA-Z0-9._-]+$` (`schema/compose-spec.json` on the `main` branch of
  [compose-spec/compose-spec](https://github.com/compose-spec/compose-spec), which publishes no
  release tags). Docker's [Networking in Compose](https://docs.docker.com/compose/how-tos/networking/)
  says: "Each service registers its name with an internal DNS server, so containers can reach each
  other using the service name directly."
- **Go's resolver** accepts `_` in a name (`isDomainName`, `net/dnsclient.go` line 116 in Go 1.27.4).
- **v0.3.1 relays to it.** byward v0.3.1 in Docker, with
  `BYWARD_UPSTREAM_URL=http://my_mcp:8000/mcp`, relayed `GET /mcp` to a container named `my_mcp` and
  got 200 (#486 Q1).
- **A public TLS certificate cannot carry it.** The CA/Browser Forum TLS Baseline Requirements
  ([`docs/BR.md`](https://github.com/cabforum/servercert/blob/main/docs/BR.md), version 2.3.1), revision
  table §1.2.1, has the row "SC012 | Sunset of Underscores in dNSNames | 2018-11-09 | 2018-12-10". The
  operative rule text was not read verbatim; only the revision-table row was.

**Prior art**, read at the version given:

| | [oauth2-proxy v7.15.6](https://github.com/oauth2-proxy/oauth2-proxy/blob/v7.15.6/pkg/util/util.go#L104-L184) | [Pomerium v0.34.1](https://github.com/pomerium/pomerium/blob/v0.34.1/internal/urlutil/url.go#L112-L157) | [Envoy v1.40.2](https://github.com/envoyproxy/envoy/blob/v1.40.2/source/common/router/config_impl.cc#L2095-L2159) | [Caddy v2.11.9](https://github.com/caddyserver/caddy/blob/v2.11.9/modules/caddyhttp/matchers.go#L257-L367) |
|---|---|---|---|---|
| Case | compares bytes | the Go side compares bytes, Envoy folds | folded at load | folded |
| Default port | `:443` must be listed | `host` matches `host:443` | per config | ignored |
| Numeric IPv4, canonical IPv6 | strings | strings | strings | strings |
| Duplicates after normalizing | – | – | – | a config error |

None of them models the browser's IPv4 spellings or its IPv6 serializer. Caddy is the clearest
model: one normalization at load, applied to both sides.

## Decision

### 1. One parser, `internal/host`

- **A new package.** `internal/host` holds `Parse`, which runs the WHATWG host parser for a special
  scheme on a `host[:port]`, and `Loopback`, a method of the parsed host.
- **What `Parse` returns:** the host's kind (name, IPv4 or IPv6), its canonical form (lower-case
  `xn--` name, dotted-decimal IPv4, shortest bracketed IPv6), its address, and its port, empty when
  absent or the scheme's default.
- **It parses only.** It knows nothing about settings and imports nothing from byward (layout rule
  3). Its errors are fixed reasons that never quote their input (ADR-0031 §1). A refusal may show the
  *parsed* address, as in "browsers read it as 127.0.0.1" (#480).
- **One `Loopback`:** `localhost` after case folding, `127.0.0.0/8` and `::1`. It replaces
  `config.isLoopback` and `oidc.loopback`. `registration.loopbackHosts` stays, as §5 says.
- **What moves into it:** the browser-IP rule, the host-name syntax, and the IDNA fold with its
  browser profile.
- **What stays outside:** the denylist's transitional fold, which matches more spellings on purpose;
  the consent page's site logic; and netip for proxy addresses.

### 2. Each class of setting has one rule

Each class's rule is a setting shape (ADR-0031 §3). It calls `internal/host` and refuses through the
shape's refusal.

_Amended 2026-11-26 (#656):_ the record of each rule's decisions is the host decision goldens: the
checks that decide on a host name or a host[:port], judged on generated input families. They are each
URL and host setting here; the public and internal Host checks; the Origin check; the CIMD client ID,
allow and trust checks; the client denylist; redirect URI validation, the loopback redirect match and
the remembered consent's redirect key; the SSRF guard's URL rule; a discovered IdP endpoint and the
oidc adapter's issuer check; what is read as loopback; the `--insecure-no-auth` loopback fence; and
the consent page's Origin check. Each package that owns such a check keeps a summary by family,
`testdata/hostdecisions.golden`, and the inputs each check passes (a denylist: the inputs it stops),
`testdata/hostdecisions.allowed`, which is edited by hand, so a widening is a reviewed line. What a
check passes today but should not is listed with its issue in `testdata/hostdecisions.residuals`.
Each such package's `FuzzHostDecisions` fuzzes the host beyond the families, on demand (#661,
`docs/maintainers/host-fuzz.md`).
`internal/testutil/hostfamilies` lists the packages and their checks. Not covered: the trusted
proxies and `X-Forwarded-For`, which take IP addresses and prefixes; the class X identifiers no
column judges, such as an assertion's `aud`; the access gate's email and hosted domains, which compare
an identity claim, not a host the proxy reads; the SSRF guard's dial-time address check, the plain-http
upstream warning and doctor's address hints, which judge resolved addresses; doctor's TLS certificate
name check and R7's duplicate-entry warnings, warnings on hosts config has already checked; and the
consent page's display of a client's site and its other-site warning. The refusal messages stay in `internal/config/testdata/hostrule.golden`.

| Class | Settings and comparisons | Rule |
|---|---|---|
| **P, published** | `BYWARD_PUBLIC_URL` | Refused unless the host and port are written exactly in their canonical form: lower case, no default port, dotted-decimal IPv4, shortest IPv6. The refusal names the canonical form or the address read. Never rewritten. A single label and `localhost` are allowed. |
| **B, browser-matched** | `BYWARD_ALLOWED_HOSTS`, `BYWARD_ALLOWED_ORIGINS`, the `Host` and `Origin` headers | Both sides parsed and compared in canonical form, ignoring one default port. Case and IPv6 spelling are folded on the setting side. A numeric IPv4 spelling and a name ending in a number are refused, naming what a browser reads. |
| **S, server-matched names** | `BYWARD_CIMD_TRUSTED_HOSTS`, `BYWARD_CIMD_ALLOWED_HOSTS`, the client denylist's hosts, and the matching at request time | Both sides parsed. A setting must be a name with at least one dot. A setting's trailing dot stays refused (the denylist strips one, as on `main`); at request time a trailing dot on the host being checked is folded, so it matches the entry without one (A2). IDN names are folded (the denylist adds its transitional fold). |
| **X, exact identifiers** | Redirect URIs, the OIDC issuer, client IDs, the assertion's `aud` | Not normalized; compared byte for byte. The loopback redirect set stays exact (§5). Only the `--dev` issuer relaxation asks `Parse(…).Loopback()`. |
| **O, operator addresses** | `BYWARD_UPSTREAM_URL`, `BYWARD_LISTEN`, `BYWARD_INTERNAL_LISTEN`, `BYWARD_TRUSTED_PROXIES`, `X-Forwarded-For` | The host part of `BYWARD_UPSTREAM_URL`, `BYWARD_LISTEN` and `BYWARD_INTERNAL_LISTEN` takes the character rule of §3 (slice 2, #522); otherwise these are left to Go's dialer, and the trusted proxies and `X-Forwarded-For` to netip. Only the no-auth loopback check asks `Parse(…).Loopback()`. |

_Amended 2026-11-26 (#524):_ "IDN names are folded" in class S means the settings' `xn--` form and the
denylist's two folds. The CIMD trust and allow check folds case and one trailing dot only, never IDNA.
Go's transport dials a Unicode host (a percent-encoded one in a client ID) by its own IDNA lookup
profile (`net/http`'s `idnaASCII`, `idna.Lookup`), which is not the browser's and dials the name as
written when it fails, so no one fold provably names the host fetched; folding with that profile would
tie a trust decision to Go's IDNA tables. A Unicode client ID host therefore never matches a listed
`xn--` one: the check only narrows. The denylist's client ID entries fold an IP address's spelling
(`host.Serialize`: `https://127.1/…` is `https://127.0.0.1/…`, `[0:0::1]` is `[::1]`; an IPv4-mapped
address is the IPv4 address it is dialed as, `[::ffff:8.8.8.8]` is `8.8.8.8`), which only
widens; `ValidateCIMDURL` still accepts a client ID at an IP address, and the SSRF guard refuses a
private one at fetch. R7's warnings cover the client denylist too, each entry keyed as the denylist
matches it (`registration.DenylistKey`, which internal/server hands to config's warning), and an
allowed host that is also trusted, which is always allowed.

**Why P is never rewritten.** IdPs and clients compare it exactly (RFC 8414 §3.3, RFC 9728 §3.3),
a browser client holds the canonical form (WHATWG §3.3, §4.4), and the IdP redirect URI is registered
as written. A silent rewrite would publish something the operator did not register.

**Why B folds but refuses a numeric spelling.** byward owns the comparison, so it can normalize both
sides. `010.0.0.1` read as `8.0.0.1` is not obvious to an operator, so it is refused, not guessed.

**The internal listener** keeps ADR-0018's rule (its 2026-11-06 amendment of §2): any IP literal,
`localhost` and the `BYWARD_ALLOWED_HOSTS` names, on any port of up to 5 digits. Its `Host` header
is parsed as class B, so those names are compared in canonical form.

_Amended 2026-11-26 (#644):_ the five URL settings (the public URL, the upstream URL, the resource
documentation, the OIDC issuer and the allowed origins) refuse an IPv6 zone with one reason, as WHATWG
URL §3.1's "Support for <zone_id> is intentionally omitted" says a URL cannot carry one; the upstream
URL, the resource documentation and the OIDC issuer took one before. A CIMD client ID on the client
denylist (#524) is refused for a zone with the same reason. `host.Split` is the one bracket rule,
which `host.Parse`, `host.Canonical`, `host.Hostname` and the config's host:port check share. The
internal listener reads its `Host` header through it, so a header that names no host (a bracketed
name or IPv4 address, a stray or unclosed bracket, text after an IPv6 address's port, or a port that
is not up to 5 digits) gets 421, where some of these passed before.

### 3. One set of host-name characters

Every host setting in classes P, B, S and O accepts ASCII letters, digits, `-`, `.` and `_` in a
host name, and refuses `~ ! $ & ' ( ) * + , ; =` and `%`. An internationalised name is written in
its `xn--` form. Class X is not refused by this set: its identifiers come from clients and the IdP
and are compared exactly (§2).

- **The refused characters are allowed by RFC 3986 and by browsers** (WHATWG §3.2; `~` and `$`
  parse in Node). No DNS name uses them, and refusing them keeps a pasted secret out of the host:
  `S3CRET~tok` is refused, and the refusal can name the character's position without printing the
  value.
- **`_` is accepted everywhere.** Compose service names hold it, and v0.3.1 relays to one. Refusing it
  in P or S would prevent no real failure:
  - browsers accept it;
  - a public certificate cannot carry it, so an https public URL with `_` already fails at the
    certificate (a private CA's certificate can);
  - a CIMD document on such a host cannot be fetched over https with a public certificate.

  This replaces #486 Q1, which accepted `_` only in classes O and B (#486 Q3).
- **Residue.** A pasted secret with no documented prefix that holds only accepted characters, such
  as `s3cret_tok`, is a valid host and can appear in `--print-config`. ADR-0031 §2 records this gap;
  a documented prefix such as `ghp_` is refused by ADR-0031 §2's prefix list, not by this set.

### 4. Behaviour changes against `main`

**Newly refused at startup.** These are breaking, each with an upgrade note:

| # | Change |
|---|---|
| R1 | A public URL with an upper-case name is refused, naming the lower-case form. On `main` since #481. |
| R2 | A public URL with the scheme's default port (`https://h:443/mcp`, `http://localhost:80/mcp`) is refused, naming the form without it (#484). |
| R3 | `BYWARD_ALLOWED_HOSTS` with a numeric IPv4 spelling (`127.1`, `0x7f.0.0.1`, `010.0.0.1`, `2130706433`) is refused, naming the address browsers read, instead of being rewritten (#480). |
| R4 | `BYWARD_ALLOWED_HOSTS` with a name ending in a number (`mcp.10`, `10.0.0.999`) is refused. |
| R5 | The CIMD lists refuse a numeric IPv4 spelling and a name ending in a number, as the client denylist already does. |
| R6 | The CIMD lists refuse IP addresses. |
| R7 | Duplicates after folding (`A.example,a.example`) in the allowed hosts, the origins and the CIMD lists are a warning, not an error. |
| D4 | A host holding `~ ! $ & ' ( ) * + , ; =` or `%` is refused in classes P, B, S and O (§3). |

**Newly accepted or matched:**

| # | Change |
|---|---|
| A1 | `Loopback` folds case: `LOCALHOST` is loopback for the `--dev` OIDC issuer, the oidc adapter's http endpoints and the no-auth listen address (#482). The issuer is still compared exactly by the IdP adapter. |
| A2 | The CIMD trust check folds a trailing dot on the client ID's host, so `https://claude.ai./…` is the trusted `claude.ai`. A trailing dot in the CIMD lists themselves stays refused. The document's `client_id` must still equal its URL exactly. |
| A3 | The `Origin` header is canonicalized at request time (`https://127.1`, `https://[0:0::1]`) and matched against the canonical entry. Browsers already send the canonical form. |

**Unchanged on purpose:** redirect URIs and the issuer are compared exactly (§5); apart from the
character rule on their host part (D4), the upstream URL and the listen addresses are left to Go's
dialer, and the trusted proxies to netip; and a trailing dot in a setting stays refused (WHATWG §3.1),
except for the denylist's strip.

### 5. ADR-0009's loopback redirect set is unchanged

A redirect URI's loopback hosts stay the exact literals `127.0.0.1`, `[::1]` and `localhost`
(ADR-0009 §2). A redirect URI is an exact identifier (class X), and RFC 8252 §7.3 makes the port the
only loopback exception. Folding `LOCALHOST` or reading `127.1` there would accept a redirect URI the
client did not register (RFC 9700 §4.1.3). `Loopback` (§1) answers a different question: whether an
operator's address is on this machine. So it may fold.

### 6. The IDNA fold is tested against published suites

The slice that builds `internal/host` pins two suites as `testdata`:

- the host and `toascii` cases of the web-platform-tests URL tests;
- Unicode's UTS #46 conformance file for 17.0.0. Go 1.27 builds `x/net/idna` v0.62.0's Unicode
  17.0.0 tables (`tables17.0.0.go`, `//go:build go1.27`).

Each mismatch is listed as a known deviation with its reason, and the test fails on a new one. The
two suites are bumped together when Go's Unicode version moves. The slice checks their file names
and download paths.

_Amended 2026-11-21 (#521):_ the UTS #46 suite is WPT's `url/resources/IdnaTestV2.json`, not
Unicode's `IdnaTestV2.txt`. UTS #46 §8 says the Unicode file "only provides test cases for
UseSTD3ASCIIRules=true", while the WHATWG URL Standard runs with it false (§3.3), and WPT's file is
its conversion to the cases browsers are tested against. It is pinned at the last WPT commit before
the file moved to Unicode 18.0.0, to match Go 1.27's 17.0.0 tables; `toascii.json` and
`urltestdata.json`'s host cases are pinned at the latest. The commits, checksums and deviations are in
`internal/host/testdata/wpt/README.md`.

## Consequences

- **Delivery** follows ADR-0031's work, in four slices. Each is a breaking-change PR with its own
  release note:
  1. `internal/host`, with `Parse`, `Loopback`, the conformance suites and A1 (#521). It moves code
     and changes no other behaviour. It starts after #511, which rewrites the same parse functions.
  2. Class P (R2), and the character rule (D4) on class O's host part (#522).
  3. Class B (R3, R4, R7, A3).
  4. Class S (R5, R6, A2).

  Slices 2–4 start after #513, so they use its final refusal format and reasons.
- **One fix reaches every setting.** #480 and #482 stop being separate fixes; each is a test of
  `internal/host`.
- **Upgrade cost** of changing a public URL to satisfy R1 or R2, seen in the v0.3.1 upgrade run (#491):
  - **Re-register.** The IdP redirect URI must be registered again in the new form.
  - **Refresh tokens keep working,** except one whose refresh names the old URL as its `resource`,
    which gets `invalid_target`.
  - **Old access tokens and pending codes get 401,** and a user who signs in again sees consent once.
- **Messages change** for the host settings, and the tests that pin them change too.

## Considered options

- **Rewrite a numeric IPv4 spelling in `BYWARD_ALLOWED_HOSTS`,** as on `main`: rejected. It
  silently turns `010.0.0.1` into a different address.
- **Keep names ending in a number in `BYWARD_ALLOWED_HOSTS`** for non-browser clients: rejected for
  consistency with the other browser-matched settings (R4).
- **Duplicates after folding as a config error** (Caddy): rejected for a warning (R7). Two spellings
  of one host do no harm once folded.
- **Refuse `LOCALHOST` in `Loopback`,** as #481 refuses upper case in the public URL: rejected. The
  operator's address names the same host; a published identity is a different rule.
- **A character set per class** (#486 Q1: `_` only in classes O and B): rejected by #486 Q3, §3.
- **Differential fuzzing against a WHATWG implementation:** rejected. It needs a second runtime in the
  test path; the published suites (§6) test the same fold.
