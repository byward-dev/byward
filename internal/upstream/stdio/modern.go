//go:build linux || darwin

package stdio

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// The modern era (2026-07-28): no sessions, every request carries its own metadata, and one
// upstream process serves all of a user's MCP clients (ADR-0003 §4). Their requests share one
// stdio channel, so the proxy rewrites each request id and progress token to one of its own and
// maps them back on the way out; nothing else in a message is touched.
const (
	// modernVersion is the first protocol version without initialize; dates compare as strings.
	modernVersion = "2026-07-28"
	// probeTimeout bounds the server/discover probe; a legacy server may never answer it.
	probeTimeout = 10 * time.Second
	// legacyVerdictTTL is how long "this upstream is not modern" is kept, so one failed probe does
	// not hold for the life of the proxy.
	legacyVerdictTTL = 10 * time.Minute
	// probeID is the id of the proxy's own server/discover.
	probeID = `"byw-probe"`
)

var (
	pathID       = jsonPath{"id"}
	pathVersion  = jsonPath{"params", "_meta", "io.modelcontextprotocol/protocolVersion"}
	pathToken    = jsonPath{"params", "_meta", "progressToken"}
	pathLogLevel = jsonPath{"params", "_meta", "io.modelcontextprotocol/logLevel"}
	pathProgress = jsonPath{"params", "progressToken"}
)

// probeRequest is the proxy's server/discover: does the upstream speak the modern era?
var probeRequest = []byte(`{"jsonrpc":"2.0","id":` + probeID + `,"method":"server/discover","params":{"_meta":{` +
	`"io.modelcontextprotocol/protocolVersion":"` + modernVersion + `",` +
	`"io.modelcontextprotocol/clientInfo":{"name":"byward","version":"probe"},` +
	`"io.modelcontextprotocol/clientCapabilities":{}}}}`)

// isModern reports whether a session-less message asks for the modern era: its _meta names a
// protocol version from 2026-07-28 on. An unparsable message is not modern; the legacy path
// refuses it.
func isModern(msg []byte) bool {
	at, err := locate(msg, pathVersion)
	if err != nil || at[0] == nil {
		return false
	}
	var v string
	return json.Unmarshal(at[0].value(msg), &v) == nil && v >= modernVersion
}

// capability is what the proxy has learned about the upstream's era.
type capability struct {
	mu          sync.Mutex
	modern      bool
	legacyUntil time.Time
}

func (c *capability) known() (modern, legacy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.modern, !c.modern && time.Now().Before(c.legacyUntil)
}

func (c *capability) set(modern bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.modern = modern
	if !modern {
		c.legacyUntil = time.Now().Add(legacyVerdictTTL)
	}
}

// userConn is a user's modern-era upstream process and the requests in flight on it.
type userConn struct {
	key string
	p   *Process
	log *slog.Logger

	mu      sync.Mutex
	next    uint64
	byID    map[string]*modernRequest // by proxy id
	byToken map[string]*modernRequest // by proxy progress token
	probe   chan []byte               // the probe's answer
	ended   chan struct{}

	probeOnce sync.Once // concurrent first requests share one probe
	modern    bool
}

// modernRequest is one client request in flight on a userConn.
type modernRequest struct {
	id, token []byte // the client's own, restored on the way out; token nil when none
	proxyID   string
	proxyTok  string
	logs      bool // asked for notifications/message (io.modelcontextprotocol/logLevel)
	out       chan []byte
	final     chan []byte
}

func newUserConn(key string, p *Process, log *slog.Logger) *userConn {
	return &userConn{key: key, p: p, log: log, byID: map[string]*modernRequest{}, byToken: map[string]*modernRequest{},
		probe: make(chan []byte, 1), ended: make(chan struct{})}
}

// modernPost serves one session-less modern-era POST.
func (b *Bridge) modernPost(w http.ResponseWriter, r *http.Request, id Identity, msg []byte, env envelope) {
	if modern, legacy := b.cap.known(); legacy && !modern {
		b.legacyFallback(w)
		return
	}
	switch env.kind() {
	case kindResponse: // the modern era has no server-to-client requests to answer (MRTR instead)
		writeRPCError(w, http.StatusBadRequest, nil, codeInvalidRequest, "Invalid Request: no request awaits a client response")
		return
	case kindNotification:
		if env.Method == "notifications/cancelled" {
			// Over HTTP, closing the response stream cancels; an id here could be any client's.
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	var at []*span
	if env.kind() == kindRequest { // refused before any process starts
		var err error
		if at, err = requestIDs(msg); err != nil {
			writeRPCError(w, http.StatusBadRequest, nil, codeInvalidRequest, "Invalid Request: "+err.Error())
			return
		}
	}
	c, release, ok := b.userConn(w, r, id)
	if !ok {
		return
	}
	defer release()
	if env.kind() == kindNotification {
		if err := c.p.Send(r.Context(), msg); err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	c.request(w, r, msg, at)
}

// requestIDs locates a request's id, progress token and log level, refusing what is ambiguous:
// the ids are rewritten, and a wrong guess would route one client's answer to another.
func requestIDs(msg []byte) ([]*span, error) {
	at, err := locate(msg, pathID, pathToken, pathLogLevel)
	if err == nil {
		err = scalarID(at[0].value(msg))
	}
	if err == nil && at[1] != nil {
		err = scalarID(at[1].value(msg))
	}
	return at, err
}

// legacyFallback is the answer to a modern request the upstream cannot serve: no modern error
// code, so a dual-era client falls back to initialize (2026-07-28 transports, backwards
// compatibility).
func (b *Bridge) legacyFallback(w http.ResponseWriter) {
	writeRPCError(w, http.StatusBadRequest, nil, codeInvalidRequest,
		"Bad Request: this server speaks MCP 2025-11-25; start a session with initialize")
}

// userConn returns the user's modern-era process, spawning and probing it if needed, with a lease.
// On failure it has answered the request.
func (b *Bridge) userConn(w http.ResponseWriter, r *http.Request, id Identity) (*userConn, func(), bool) {
	key := "user:" + id.user()
	p, release, err := b.c.Manager.Get(r.Context(), key, id)
	if err != nil {
		b.startFailed(w, r, id, err)
		return nil, nil, false
	}
	b.mu.Lock()
	c := b.users[key]
	fresh := c == nil || c.p != p
	if fresh {
		c = newUserConn(key, p, b.c.Log.With("process", p.PID(), "user_key", id.Subject))
		b.users[key] = c
	}
	b.mu.Unlock()
	if fresh {
		go func() {
			c.pump()
			b.mu.Lock()
			if b.users[key] == c {
				delete(b.users, key)
			}
			b.mu.Unlock()
		}()
	}
	if modern, _ := b.cap.known(); !modern && !c.probed(r.Context()) {
		release()
		b.cap.set(false)
		p.stop("not_modern")
		b.legacyFallback(w)
		return nil, nil, false
	}
	b.cap.set(true)
	return c, release, true
}

// probed asks the process server/discover, once; a DiscoverResult means it speaks the modern era.
func (c *userConn) probed(ctx context.Context) bool {
	c.probeOnce.Do(func() { c.modern = c.discover(ctx) })
	return c.modern
}

func (c *userConn) discover(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
	defer cancel()
	if c.p.Send(ctx, probeRequest) != nil {
		return false
	}
	select {
	case m := <-c.probe:
		var res struct {
			Result struct {
				SupportedVersions []string `json:"supportedVersions"`
			} `json:"result"`
		}
		return json.Unmarshal(m, &res) == nil && len(res.Result.SupportedVersions) > 0
	case <-c.ended:
		return false
	case <-ctx.Done():
		return false
	}
}

// request relays one modern-era request under proxy-chosen ids.
func (c *userConn) request(w http.ResponseWriter, r *http.Request, msg []byte, at []*span) {
	q := c.register(at[0].value(msg), at[1], msg, at[2] != nil)
	defer c.unregister(q)
	edits := []edit{{at[0], []byte(q.proxyID)}}
	if at[1] != nil {
		edits = append(edits, edit{at[1], []byte(q.proxyTok)})
	}
	if err := c.p.Send(r.Context(), replace(msg, edits...)); err != nil {
		c.log.WarnContext(r.Context(), "relaying to the upstream process failed", "request_id", logging.RequestID(r.Context()), "error", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	out := startSSE(w)
	for {
		select {
		case m := <-q.out:
			if out.write(m) != nil {
				c.cancel(q)
				return
			}
		case m := <-q.final:
			for drained := false; !drained; {
				select {
				case o := <-q.out:
					_ = out.write(o)
				default:
					drained = true
				}
			}
			_ = out.write(m)
			return
		case <-c.ended:
			_ = out.write(rpcError(q.id, codeInternalError, "upstream process exited"))
			return
		case <-r.Context().Done():
			c.cancel(q) // closing the stream cancels the request (2026-07-28 transports)
			return
		}
	}
}

func (c *userConn) register(id []byte, token *span, msg []byte, logs bool) *modernRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	n := strconv.FormatUint(c.next, 10)
	q := &modernRequest{id: id, proxyID: `"byw-` + n + `"`, logs: logs, out: make(chan []byte, streamBuffer), final: make(chan []byte, 1)}
	c.byID[q.proxyID] = q
	if token != nil {
		q.token, q.proxyTok = token.value(msg), `"byw-t`+n+`"`
		c.byToken[q.proxyTok] = q
	}
	return q
}

func (c *userConn) unregister(q *modernRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byID[q.proxyID] == q {
		delete(c.byID, q.proxyID)
	}
	if q.proxyTok != "" && c.byToken[q.proxyTok] == q {
		delete(c.byToken, q.proxyTok)
	}
}

// cancel tells the upstream to stop work on q, which nobody will read any more.
func (c *userConn) cancel(q *modernRequest) {
	c.unregister(q)
	go func() { // never from a reader: the upstream may be blocked writing to us
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		defer cancel()
		_ = c.p.Send(ctx, []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":`+q.proxyID+`}}`))
	}()
}

// pump routes every upstream message until stdout closes.
func (c *userConn) pump() {
	for msg := range c.p.Messages() {
		c.route(msg)
	}
	close(c.ended)
}

// route sends one upstream message to the request it belongs to, under the client's own ids.
func (c *userConn) route(msg []byte) {
	env, err := parseEnvelope(msg)
	if err != nil || env.kind() == kindInvalid {
		c.log.Warn("upstream wrote a line that is not a JSON-RPC message", "reason", "invalid_upstream_message")
		return
	}
	switch env.kind() {
	case kindResponse:
		c.routeResponse(msg, string(compactID(env.ID)))
	case kindRequest: // a modern server MUST NOT write requests to stdout (2026-07-28 stdio)
		c.log.Warn("upstream sent a request, which the modern era does not allow", "reason", "upstream_request", "method", env.Method)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			defer cancel()
			_ = c.p.Send(ctx, rpcError(env.ID, codeInternalError, "server-to-client requests are not part of MCP 2026-07-28"))
		}()
	case kindNotification:
		c.routeNotification(msg, env.Method)
	}
}

func (c *userConn) routeResponse(msg []byte, proxyID string) {
	if proxyID == probeID {
		select {
		case c.probe <- msg:
		default:
		}
		return
	}
	c.mu.Lock()
	q := c.byID[proxyID]
	c.mu.Unlock()
	at, err := locate(msg, pathID)
	if q == nil || err != nil {
		c.log.Warn("upstream response for no waiting request", "reason", "response_unrouted")
		return
	}
	select {
	case q.final <- replace(msg, edit{at[0], q.id}):
	default:
	}
}

func (c *userConn) routeNotification(msg []byte, method string) {
	switch method {
	case "notifications/progress":
		at, err := locate(msg, pathProgress)
		if err != nil || at[0] == nil {
			c.drop(method, "progress_unrouted")
			return
		}
		c.mu.Lock()
		q := c.byToken[string(compactID(at[0].value(msg)))]
		c.mu.Unlock()
		if q == nil {
			c.drop(method, "progress_unrouted")
			return
		}
		c.deliver(q, replace(msg, edit{at[0], q.token}), method)
	case "notifications/message":
		// No correlation key on stdio (2026-07-28 logging): delivered only when exactly one request
		// in flight asked for log messages; otherwise it could reach the wrong client.
		c.mu.Lock()
		var only *modernRequest
		n := 0
		for _, q := range c.byID {
			if q.logs {
				only, n = q, n+1
			}
		}
		c.mu.Unlock()
		if n != 1 {
			c.drop(method, "log_unrouted")
			return
		}
		c.deliver(only, msg, method)
	default:
		c.drop(method, "notification_unrouted")
	}
}

func (c *userConn) deliver(q *modernRequest, msg []byte, method string) {
	select {
	case q.out <- msg:
	default:
		c.drop(method, "stream_full")
	}
}

func (c *userConn) drop(method, reason string) {
	c.log.Warn("upstream notification dropped", "reason", reason, "method", method)
}

// startFailed answers a request whose process could not be had.
func (b *Bridge) startFailed(w http.ResponseWriter, r *http.Request, id Identity, err error) {
	if errors.Is(err, errBusy) {
		b.c.Log.WarnContext(r.Context(), "stdio process cap full: every process is in use", "request_id", logging.RequestID(r.Context()),
			"reason", "process_cap", "user_key", id.Subject)
		w.Header().Set("Retry-After", busyRetryAfter)
		http.Error(w, "upstream busy", http.StatusServiceUnavailable)
		return
	}
	b.c.Log.WarnContext(r.Context(), "cannot start the upstream process", "request_id", logging.RequestID(r.Context()), "error", err)
	http.Error(w, "upstream unavailable", http.StatusBadGateway)
}
