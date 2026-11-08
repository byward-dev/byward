//go:build linux || darwin

package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnvDownstreamTokenSocket names the Unix socket an upstream process asks for its user's downstream
// API token on, when On-Behalf-Of is on (ADR-0017, amended for stdio).
const EnvDownstreamTokenSocket = "BYWARD_DOWNSTREAM_TOKEN_SOCKET"

// Errors a token socket answers with, besides the ones Config.DownstreamToken gives.
const (
	// TokenRefused: the peer is neither the upstream process nor one of its descendants.
	TokenRefused = "refused"
	// TokenBadRequest: the request was not one JSON object on one line.
	TokenBadRequest = "bad_request"
)

// DownstreamToken is a downstream API token for a process's user, or the error code that says why
// there is none (consent_required, interaction_required, sign_in_expired, no_user, unavailable,
// failed). AccessToken is set exactly when Error is empty.
type DownstreamToken struct {
	AccessToken string
	ExpiresAt   time.Time
	Error       string
}

const (
	tokenSocketName = "token.sock"
	// maxSocketPath is the longest socket path both platforms accept (sun_path: 104 bytes on
	// macOS with its NUL, 108 on Linux).
	maxSocketPath = 103
	// tokenAnswerTimeout bounds one connection: the On-Behalf-Of exchange takes at most 30 s
	// (downstream.ExchangeTimeout), and a peer that stalls must not block the next one for longer.
	tokenAnswerTimeout = 40 * time.Second
	// tokenWriteMargin is kept from the connection's deadline for writing the answer, so an answer
	// that takes its whole time still reaches the peer.
	tokenWriteMargin = 5 * time.Second
	maxTokenRequest  = 4 << 10
	// refusalWait is how long a refused peer is given to send its request, which is read and
	// discarded so its write does not fail with EPIPE (#244). It is short: the socket serves one
	// connection at a time, and a stranger must not hold it for a legitimate process's bound.
	refusalWait = time.Second
	// maxRefusedRequest bounds what is read from a refused peer before answering, past the socket
	// buffer a large request would otherwise fill.
	maxRefusedRequest = 64 << 10
	// maxAncestry bounds the walk from a peer up to the upstream process.
	maxAncestry = 64
)

// tokenSocket serves one upstream process's token socket in its session directory.
type tokenSocket struct {
	ln     *net.UnixListener
	path   string
	log    *slog.Logger
	answer func(context.Context) DownstreamToken
	// timeout bounds a connection and margin is kept of it for the answer's write; refusalWait
	// bounds the read of a refused peer's request: tokenAnswerTimeout, tokenWriteMargin and
	// refusalWait, shorter in tests.
	timeout, margin, refusalWait time.Duration
}

// listenTokenSocket opens the token socket in dir, readable and writable by our uid only, inside
// a directory that is ours alone.
func listenTokenSocket(dir string, log *slog.Logger, answer func(context.Context) DownstreamToken) (*tokenSocket, error) {
	path := filepath.Join(dir, tokenSocketName)
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("stdio: token socket path %s is longer than %d bytes; set a shorter temporary directory (TMPDIR)", path, maxSocketPath)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("stdio: token socket: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("stdio: token socket: %w", err)
	}
	return &tokenSocket{ln: ln, path: path, log: log, answer: answer, timeout: tokenAnswerTimeout, margin: tokenWriteMargin,
		refusalWait: refusalWait}, nil
}

// serve answers requests from root (the upstream process) and its descendants until the socket is
// closed, one at a time.
func (s *tokenSocket) serve(root int) {
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			return // closed when the process has exited
		}
		s.handle(c, root)
	}
}

func (s *tokenSocket) close() { _ = s.ln.Close() }

// handle answers one connection with one JSON line: the token, or an error code. The token is
// never logged.
func (s *tokenSocket) handle(c *net.UnixConn, root int) {
	defer func() { _ = c.Close() }()
	deadline := time.Now().Add(s.timeout)
	_ = c.SetDeadline(deadline)
	reply := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = c.Write(append(b, '\n'))
	}
	refuse := func(code string) { reply(map[string]string{"error": code}) }
	peer, ok, err := peerIsDescendant(c, root)
	if !ok {
		attrs := []any{"reason", "token_peer_refused", "peer_process", peer}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		s.log.Warn("token socket: the peer is not the upstream process or one of its descendants", attrs...)
		// Read its request before answering: a peer whose write found the connection already closed
		// would get EPIPE, not the refusal (#244). The read takes at most refusalWait and
		// maxRefusedRequest, so a silent or flooding stranger holds the socket only briefly.
		_ = c.SetReadDeadline(time.Now().Add(s.refusalWait))
		discardLine(c, maxRefusedRequest)
		refuse(TokenRefused)
		return
	}
	line, err := bufio.NewReaderSize(c, maxTokenRequest).ReadSlice('\n')
	var req map[string]json.RawMessage
	if err != nil || json.Unmarshal(line, &req) != nil || req == nil {
		refuse(TokenBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline.Add(-s.margin))
	defer cancel()
	t := s.answer(ctx)
	if t.Error != "" || t.AccessToken == "" {
		code := t.Error
		if code == "" {
			code = "failed"
		}
		refuse(code)
		return
	}
	reply(map[string]string{"access_token": t.AccessToken, "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339)})
}

// discardLine reads from r up to the first newline, at most limit bytes, or until a read fails.
func discardLine(r io.Reader, limit int) {
	br := bufio.NewReaderSize(io.LimitReader(r, int64(limit)), maxTokenRequest)
	for {
		if _, err := br.ReadSlice('\n'); !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// errNotDescendant is reported when a peer's ancestry never reaches the upstream process.
var errNotDescendant = errors.New("not a descendant of the upstream process")

// peerIsDescendant reports whether the peer of c runs as our uid and is root or a descendant of
// root. peer is the peer's process ID, or 0 when it cannot be read.
func peerIsDescendant(c *net.UnixConn, root int) (peer int, ok bool, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var cred peerCred
	var credErr error
	if err := rc.Control(func(fd uintptr) { cred, credErr = readPeerCred(int(fd)) }); err != nil {
		return 0, false, err
	}
	if credErr != nil {
		return 0, false, credErr
	}
	defer cred.release()
	if cred.uid != os.Getuid() {
		return cred.pid, false, fmt.Errorf("peer runs as uid %d", cred.uid)
	}
	if err := descends(cred.pid, root, parentOf); err != nil {
		return cred.pid, false, err
	}
	// The ancestry was read from the process table after the peer connected. Where the kernel pins
	// the peer (a pidfd), check it is still the same process, so a peer that exited and whose PID
	// was reused inside the upstream's tree is not taken for its successor.
	if !cred.stillSame() {
		return cred.pid, false, errors.New("the peer exited while it was checked")
	}
	return cred.pid, true, nil
}

// descends reports nil when pid is root or one of its descendants, following parent from pid.
func descends(pid, root int, parent func(int) (int, error)) error {
	for range maxAncestry {
		if pid == root {
			return nil
		}
		if pid <= 1 {
			return errNotDescendant
		}
		next, err := parent(pid)
		if err != nil {
			return err
		}
		pid = next
	}
	return errNotDescendant
}
