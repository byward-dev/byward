# Fuzz the host checks

Every check that reads a host has its decisions recorded by input family (#656, ADR-0032): a summary
in each package's `testdata/hostdecisions.golden`, and the inputs it passes in
`testdata/hostdecisions.allowed`, edited by hand. The families are fixed, so a form outside them goes
unseen. Each package that owns such a check also has `FuzzHostDecisions` (#661), which fuzzes the
host[:port] the checks read.

## Run it

```sh
mise run test:fuzz:host              # 2 minutes per target
FUZZTIME=60s mise run test:fuzz:host # shorter
```

The nightly `fuzz` workflow leaves these targets out. `mise run test` runs only their seeds: one
host per family, wrap and port.

## What fails

For each check, on each fuzzed host, placed as the check's own inputs place a host (bare, or in a URL
with their scheme and path):

| Rule | Checks | Fails when |
|---|---|---|
| No widening | the checks against a fixed list: the public Host, the Origin and consent Origin, the CIMD allowed and trusted hosts | the check passes an input that `hostdecisions.allowed` lists in no ASCII letter case |
| No widening, denylist | the client denylist's client ID and redirect | the check no longer stops an input that `hostdecisions.allowed` lists, in some ASCII letter case, as stopped |
| Round trip | every check but a denylist | the check passes an ASCII input and refuses it with its host as browsers write it (`host.Serialize`). A non-ASCII host has no such form here, because `Serialize` maps nothing as UTS 46 does |
| No panic | every check | the check panics |

A check that takes an open set of hosts has no widening rule. A list of inputs cannot hold that set,
and a second grammar to stand in for it would be an oracle of its own. These checks include:

- a setting's parser;
- the SSRF guard;
- the internal Host check, which passes any IP literal;
- loopback as written, which is all of 127.0.0.0/8.

## When it fails

Go writes the failing input under the package's `testdata/fuzz/FuzzHostDecisions/`, and
`build/fuzz/crashers/` keeps a copy. `go test ./internal/<package>/` replays it.

First add the form to a family in `internal/testutil/hostfamilies`: the baseline only lists the
golden's own inputs. The golden test then names the decision, and you take one of these routes:

- **The check is wrong:** fix it.
- **The check is right:** add the input's line to `hostdecisions.allowed` by hand, and say why in
  the PR.
- **A known gap, fixed later:** add the line to `hostdecisions.allowed` and to
  `hostdecisions.residuals`, with its issue.

Then delete the input from `testdata/fuzz/`, because the golden pins the form from now on.
