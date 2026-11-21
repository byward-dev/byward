# web-platform-tests URL host suites

Pinned copies of two files from [web-platform-tests](https://github.com/web-platform-tests/wpt)
`url/resources/`, and the host cases of a third, for `TestParseAgreesWithTheWPTHostSuites`
(ADR-0032 §6). They are licensed under the 3-Clause BSD License in `LICENSE.md`, copied from WPT.

| File | WPT commit | SHA-256 |
|---|---|---|
| `IdnaTestV2.json` | [b63305b743ed9ce2725d4ae09c5c8f0c40d8e6e1](https://github.com/web-platform-tests/wpt/blob/b63305b743ed9ce2725d4ae09c5c8f0c40d8e6e1/url/resources/IdnaTestV2.json) (2026-06-25) | `338192b9815dbdace6c035cb1acd50cd737070cd67d6e3f620d2543f63eb0cbb` |
| `toascii.json` | [dca32277cbf3d40b3ec20bba999a987b0ea51ed7](https://github.com/web-platform-tests/wpt/blob/dca32277cbf3d40b3ec20bba999a987b0ea51ed7/url/resources/toascii.json) (2026-11-13) | `644eba9d5b593df8095cfa307222f3014542ff9cc02d555f8e5660059d80470f` |
| `urltestdata-hosts.json`, derived from `urltestdata.json` | [dca32277cbf3d40b3ec20bba999a987b0ea51ed7](https://github.com/web-platform-tests/wpt/blob/dca32277cbf3d40b3ec20bba999a987b0ea51ed7/url/resources/urltestdata.json) (2026-11-13); the source's SHA-256 is `f11f7dc444cc9dcb01fd5c1de13720cdc55e579d0f0412e760c081403e3c4684` | `55e7979fb773e0f8d913a9de6101927a1b0ff8d8bff2754482abd053969bf35b` |
| `LICENSE.md` | dca32277cbf3d40b3ec20bba999a987b0ea51ed7 | |

`dca32277` was the latest commit touching `url/resources` when these were taken (2026-11-21).

`urltestdata-hosts.json` keeps the 284 entries of `urltestdata.json` with a special scheme (ftp, http,
https, ws, wss) whose host can be cut out as written: no userinfo, whitespace, controls or
backslashes. It keeps each entry's `input`, `host` and `failure`. The whole file is not kept: its
userinfo URLs (such as `user:pass@host.example`) look like email addresses to the repository's privacy check,
and no host case needs them.

## Why IdnaTestV2.json is from an older commit

`IdnaTestV2.json` is WPT's conversion of Unicode's UTS #46 conformance file (`IdnaTestV2.txt`) for
URL use. Its generator, `url/tools/IdnaTestV2-parser.py`, downloads
`https://unicode.org/Public/idna/latest/IdnaTestV2.txt` and keeps only the cases that apply to
browsers (`--exclude-ipv4-like`, `--exclude-std3`, `--exclude-bidi`, as the file's second line says).
The file does not record its Unicode version. Its history does:

- `40fc257a` (2025-09-18): "Update IdnaTestV2.json for Unicode 17.0.0";
- `b63305b7` (2026-06-25): "IDNA cannot fail ASCII domains, even if they start with xn--";
- `13748c36` (2026-10-04): "Update IDNA Test JSON to Unicode 18.0.0".

So `b63305b7` is the last version for Unicode 17.0.0, the version of Go 1.27's IDNA tables
(`golang.org/x/net/idna`, `tables17.0.0.go`, `//go:build go1.27`). This is read from the commit
messages; the file itself names no version. Bump it together with Go's Unicode version.

UTS #46's own file is not pinned: it "only provides test cases for UseSTD3ASCIIRules=true" (UTS #46
§8), while browsers run with it false; WPT's conversion is the set browsers are tested against.

## Deviations

`TestParseAgreesWithTheWPTHostSuites` lists each case `host.Parse` reads differently, with its
reason and what `Parse` reads instead, and fails on a new one. It also pins each file's case count
(2670, 87 and 284), so a refresh that truncates a file fails:

- a bare IPv6 address (`http://2001::1`): `Parse` takes it whole, as `BYWARD_ALLOWED_HOSTS` gives one;
- percent-encoded hosts (5 cases): the URL parser decodes them first; `Parse` does not, since no
  setting or header byward reads carries one.

## Refreshing

1. Pick the new commit: `gh api "repos/web-platform-tests/wpt/commits?path=url/resources&per_page=1"`.
   For `IdnaTestV2.json`, pick the commit whose Unicode version matches Go's `x/net/idna` tables.
2. Download each file from `https://raw.githubusercontent.com/web-platform-tests/wpt/<commit>/url/resources/<file>`,
   and `LICENSE.md` from the repository root. Regenerate `urltestdata-hosts.json` from the downloaded
   `urltestdata.json`: `BYWARD_WPT_URLTESTDATA=<its absolute path> go test -run TestRegenerateTheURLHostSuiteFromURLTestData ./internal/host/`
   (the path is read from the package directory).
3. Update the table above (commit, date, `shasum -a 256`), run `go test ./internal/host/`, and review
   each new mismatch: fix `Parse`, or list it as a deviation with its reason.
