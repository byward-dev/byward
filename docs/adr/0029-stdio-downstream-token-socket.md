# ADR-0029: stdio upstreams get downstream tokens from a token socket

- Status: Accepted
- Date: 2026-11-14
- Issue: #141 (PR #236), #181 (PR #283), #244 (PR #247), #307 (PR #312); amends ADR-0017

## Context

Recorded after the fact. The design was first written as the ADR-0017 amendment "2026-11-08 (#141:
stdio upstreams)", which stays as written; this ADR records it as a decision of its own, with the
command and checks added since.

On-Behalf-Of (ADR-0017) gives an HTTP upstream its user's downstream token in a header on every
request. A stdio process gets its environment once, when it starts, and serves one user (ADR-0003),
so a token that expires within the hour cannot reach it that way. The 2026-11-07 settings note
therefore refused On-Behalf-Of with a stdio upstream.

Every upstream process, whatever its user, runs as byward's uid, so file permissions cannot keep one
user's process away from another's token. Issue #141 asked for the threat model first: another local
process must not obtain a user's token.

Delivery mechanisms tried on 2026-11-07 (ADR-0017, #141 amendment):

- An inherited file descriptor (fd 3) does not survive `npx`: npm's child process gets only the
  standard streams. `uvx` and `sh -c` keep it, but npx servers are the common case.
- A token file would be readable by every process of byward's uid, and would store the token,
  against ADR-0017 §4.
- The token in each request's `_meta` would reach byward's own logs whenever a server logs its
  requests to stderr.

Some stdio servers and SDKs take a command that prints a token (a credential command) rather than
code that calls a socket (#181).

## Decision

1. **A token socket per process.** With On-Behalf-Of on (`BYWARD_OBO_SCOPES`), each stdio process
   gets a Unix socket, `token.sock`, in its own session directory (`os.MkdirTemp`, so 0700; the
   socket 0600), named in `BYWARD_DOWNSTREAM_TOKEN_SOCKET` in the process's environment. The process
   writes one JSON object on one line (`{}`) and reads one line back: `{"access_token","expires_at"}`
   (RFC 3339, UTC), or `{"error"}` with `consent_required`, `interaction_required`,
   `sign_in_expired`, `no_user`, `unavailable`, `failed`, `refused` or `bad_request`. The socket
   serves one connection at a time and answers within 40 s (the exchange takes at most 30 s).
2. **Which user, which grant.** The token is for the process's user, exchanged for the stored IdP
   token of the grant whose request the process served last, from the same cache as an HTTP
   upstream's. An app-only caller acts for no user: `no_user`. An expired, revoked or signed-out
   grant or stored IdP token: `sign_in_expired`; byward never refreshes IdP tokens outside a
   request, and the client's next request renews it.
3. **The same check before every request.** byward gets the token before a request reaches the
   process, as for an HTTP upstream. A refusal is answered in the proxy's name (ADR-0025 shapes,
   ADR-0017 2026-11-07) and never starts or reaches a process. A refusal on the socket by the IdP
   is recorded like one on a request: the `downstream_token_refused` audit event, the metric, the
   error log with the admin-consent URL.
4. **Who may ask: the spawned process and its descendants only.**
   - The peer's uid must be byward's (`SO_PEERCRED`; `LOCAL_PEERCRED` on macOS).
   - Its parent chain must reach the spawned process within 64 steps (`/proc/<pid>/stat`;
     `kern.proc.pid` on macOS).
   - On Linux 6.5 and later the peer is pinned with `SO_PEERPIDFD`, and its pidfd's `fdinfo` is
     read again after the walk: a peer that has exited shows `Pid: -1` and is refused. Only
     `ENOPROTOOPT` (an older kernel) goes unpinned; any other error refuses.
   - Any other peer gets `refused`, logged with its process ID. Its request is read (at most 1 s
     and 64 KiB) before the answer, so its write does not fail with a broken pipe (#244).
5. **`byward downstream-token [--json]`** is the credential command (#181). It reads only
   `BYWARD_DOWNSTREAM_TOKEN_SOCKET`, loads no configuration and logs nothing. It prints the token
   alone on stdout (with `--json`, the token and `expires_at`); on an error answer, the code alone on
   stderr and exit 1; an unset variable or wrong arguments exit 2 without asking the socket. It
   passes the ancestry check because the server starts it. The whole call is bounded at 90 s.
6. **The socket path must fit.** A socket path is at most 107 bytes on Linux and 103 on macOS. With
   On-Behalf-Of, startup, `check --offline` and `doctor` refuse a temporary directory whose longest
   session socket path would not fit, naming `TMPDIR` (#312).
7. **The host's ptrace setting is a warning, not a refusal.** With `kernel.yama.ptrace_scope` 0 or
   no Yama, one process can read another of the same uid's memory, and the token it holds. byward
   warns at startup, in `check` and in `doctor`; the operator may isolate processes by other means.
8. `BYWARD_OBO_HEADER` has no effect with a stdio upstream; setting it refuses to start.

## Consequences

- An upstream author changes one thing: read the token from the socket (or run
  `byward downstream-token`) when calling the downstream API, and ask again before `expires_at`. A
  server that reads only a static environment variable cannot get a token that expires within the
  hour without a restart.
- Older Linux kernels (before 6.5) and macOS leave a narrow race: a peer that hands its connection to
  another process and exits, with its PID reused inside the upstream's tree before the check, would
  pass. On macOS, `LOCAL_PEERPID` names the last process to use the peer's socket, so a connection
  handed on is checked against its new holder. macOS is for development only.
- Per-user isolation of upstream processes (a uid or sandbox per user) is not built: #182, open.
- A long `TMPDIR` that worked without On-Behalf-Of now refuses to start once it is turned on.

## Considered options

- An inherited file descriptor, a token file, and the token in `_meta`: rejected, see Context.
- Refuse to start when `ptrace_scope` is 0: Debian's kernel default, and the operator may isolate
  processes another way.
- No credential command: servers that take only a command would need a wrapper of their own.
