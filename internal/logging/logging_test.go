package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig"

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "json")
	h := http.Header{"Authorization": {"Bearer " + token}}
	log.Info("request",
		"authorization", "Bearer "+token, // not an allowed key
		"token", token, // not an allowed key
		"headers", h, // not an allowed key
		"error", errors.New("upstream said: Bearer "+token), // allowed key, secret value
		"reason", "Bearer "+token, // allowed key, secret value
		"value", h, // allowed key, but a header map is never logged
		"method", "POST",
	)
	out := buf.String()
	for _, leak := range []string{token, "Bearer", "authorization", "headers"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"method":"POST"`) || !strings.Contains(out, `"reason":"[REDACTED]"`) {
		t.Fatalf("expected allowed attrs: %s", out)
	}
}

// Only a credential is redacted: a Bearer or Basic value, or a JWT by its shape (see jwtShape),
// not by the letters eyj: a random base64url client ID contains them about once in a thousand
// registrations, and the operator needs it (#230).
// Prose that names a scheme before a word is redacted too: a fail-safe accepted in #242, since a
// length floor would let a short credential through.
func TestOnlyCredentialShapedValuesAreRedacted(t *testing.T) {
	for name, tc := range map[string]struct {
		value  any
		logged string
	}{
		"a client ID with eyJ":                                       {value: "dcr-Qm9eyJx_7k-eyJAbCdEfGh", logged: "dcr-Qm9eyJx_7k-eyJAbCdEfGh"},
		"a client ID with eyj":                                       {value: "dcr-xeyjq0Z-eyjAbCdEfGhIjk", logged: "dcr-xeyjq0Z-eyjAbCdEfGhIjk"},
		"a URL with eyJ and one dot":                                 {value: "https://heyJude.example/cb", logged: "https://heyJude.example/cb"},
		"a URL with .eyJ and one dot":                                {value: "https://app.eyJude/cb", logged: "https://app.eyJude/cb"},
		"a host label starting with eyj":                             {value: "https://app.eyjude.example.com/cb", logged: "https://app.eyjude.example.com/cb"},
		"a host with eyj and two dots":                               {value: "https://heyjude.example.com/cb", logged: "https://heyjude.example.com/cb"},
		"a bare JWT":                                                 {value: token, logged: redacted},
		"a JWT with _ and - in it":                                   {value: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE_Yj5jIn0.eyJzdWIiOiJ4Pz5-In0.c2ln", logged: redacted},
		"an unsigned JWT":                                            {value: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", logged: redacted},
		"a JWT cut before its signature":                             {value: "stderr: token=eyJhbGciOiJSUzI1NiJ9.eyJ1cG4iOiJh", logged: redacted},
		"a JWT whose header has a space":                             {value: "token eyAiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ4Pz5-In0.c2ln rejected", logged: redacted},
		"a JWE cut after its encrypted key":                          {value: "stderr: token=eyJhbGciOiJSU0EtT0FFUCJ9.ZW5j_cnl-dGVk", logged: redacted},
		"a spaced-header JWT cut short":                              {value: "stderr: token=eyAiYWxnIjoiUlMyNTYiLCJraWQiOiJrMCJ9.eyJzdWIiOiJ4", logged: redacted},
		"a spaced-header JWT with _ and - cut short":                 {value: "stderr: token=eyAiYWxnIjoiUlMyNTYiQ-.eyJzdWIi_x", logged: redacted},
		"a JWE whose header has a -":                                 {value: "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6Ij8-In0.ZW5j.aXY.Y3Q.dGFn", logged: redacted},
		"a spaced header ending in a lowercase letter, cut short":    {value: "stderr: token=eyAiYWxnIjoiUlMyNTYifz.eyJzdWIiOiJ4", logged: redacted},
		"a Bearer value after a -":                                   {value: "-Bearer abc", logged: redacted},
		"eyJ then a dot, with nothing between":                       {value: "eyJ.x", logged: "eyJ.x"},
		"a dot before eyJ, with nothing before the dot":              {value: ".eyJx", logged: ".eyJx"},
		"a dot before a JWT header (HoldsJWT, which config refuses)": {value: ".eyJx.", logged: redacted},
		"a payload's eyJ ending the string":                          {value: "a.eyJ", logged: redacted},
		"a vendor token in a stderr line":                            {value: "auth with " + "ghp_" + strings.Repeat("Q7", 18) + " failed", logged: redacted},
		"a URL with a password in a stderr line":                     {value: "dial postgres://app:" + "Q7q7Q7" + "@db.example/app: refused", logged: redacted},
		"a JSON line naming an origin, then an email":                {value: `{"endpoint":"https://api.example.com","user":"bob@example.com"}`, logged: `{"endpoint":"https://api.example.com","user":"bob@example.com"}`},
		"a spaced header ending in _, cut short":                     {value: "stderr: token=eyAiYWxnIjoiUlMyNTYiI_.eyJzdWIiOiJ4", logged: redacted},
		"a JWE with no encrypted key":                                {value: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiYT9iPmMifQ_..aXY.Y3Q.dGFn", logged: redacted},
		"a Bearer value":                                             {value: "Bearer opaque-token", logged: redacted},
		"a lowercase bearer value":                                   {value: "authorization: bearer opaque-token", logged: redacted},
		"a lowercase basic value":                                    {value: "authorization: basic dXNlcjpwdw==", logged: redacted},
		"a Basic value":                                              {value: "Basic dXNlcjpwdw==", logged: redacted},
		"an uppercase BASIC value":                                   {value: "BASIC dXNlcjpwdw==", logged: redacted},
		"a tab between Bearer and its token":                         {value: "authorization: Bearer\topaque-token", logged: redacted},
		"a config error that names client_secret_basic":              {value: "client_secret_file: only with client_secret_basic or client_secret_post", logged: "client_secret_file: only with client_secret_basic or client_secret_post"},
		"a Bearer value after a double quote":                        {value: `upstream said "Bearer opaque-token"`, logged: redacted},
		"three spaces between Bearer and its token":                  {value: "Bearer   opaque-token", logged: redacted},
		"a Basic credential that starts with +":                      {value: "Basic +dXNlcjpwdw==", logged: redacted},
		"a field named basic_auth":                                   {value: "missing field basic_auth in the request", logged: "missing field basic_auth in the request"},
		"a field named bearer_token":                                 {value: "missing field bearer_token in the request", logged: "missing field bearer_token in the request"},
		"a Bearer value after a JSON escape":                         {value: `{"msg":"retrying with\nBearer byw_at_opaque"}`, logged: redacted},
		"a Basic value after an escaped CRLF":                        {value: `b'GET / HTTP/1.1\r\nBasic YTpi'`, logged: redacted},
		"a Bearer value after a URL-encoded space":                   {value: "Authorization=%20Bearer opaque-token", logged: redacted},
		"prose that names a scheme, an accepted over-redaction":      {value: "the upstream wants basic auth", logged: redacted},
		"a Bearer value inside a message":                            {value: "upstream rejected Bearer opaque-token as expired", logged: redacted},
		"a Bearer value inside an error":                             {value: errors.New("upstream echoed Authorization: Bearer opaque-token"), logged: redacted},
		"a Bearer value after a colon":                               {value: "authorization:Bearer opaque-token", logged: redacted},
		"a Bearer token that starts with _":                          {value: "Bearer _opaque-token", logged: redacted},
		"a Bearer value in a printed Go header map":                  {value: "headers map[Authorization:[Bearer opaque-token]]", logged: redacted},
		"a Bearer value after a single quote":                        {value: "'Bearer opaque-token'", logged: redacted},
		"a Bearer token that starts with -":                          {value: "Bearer -pAqUe7oKen", logged: redacted},
		"a Bearer token that starts with /":                          {value: "Bearer /pAqUe7oKen", logged: redacted},
		"a name that ends in _bearer":                                {value: "unknown kind x_bearer in config", logged: "unknown kind x_bearer in config"},
		"a short Basic credential":                                   {value: "Basic YTpi", logged: redacted},
		"a scheme with no credential after it":                       {value: "the Authorization header had only Bearer ", logged: "the Authorization header had only Bearer "},
		"a JWT inside a message":                                     {value: "upstream rejected " + token + " as expired", logged: redacted},
		"a JWT inside an error":                                      {value: errors.New("verify " + token + ": expired"), logged: redacted},
		"a Stringer with a JWT":                                      {value: stringer("verify " + token), logged: redacted},
		"an error with an eyJ identifier":                            {value: errors.New("unknown client dcr-eyJq0Z"), logged: "unknown client dcr-eyJq0Z"},
		// User keys a real user may have, accepted over-redactions too (#594): revoke-user still takes them.
		"a name with Basic in it":                 {value: "Ann Basic Lee", logged: redacted},
		"a username shaped like a JWT":            {value: "eyJohn.Smith", logged: redacted},
		"an email with eyJ and two dots after it": {value: "heyJoe.Smith.Jr@example.com", logged: redacted},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, "json").Info("x", "reason", tc.value)
			var line struct{ Reason string }
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("log line %q: %v", buf.String(), err)
			}
			if line.Reason != tc.logged {
				t.Fatalf("reason logged as %q, want %q", line.Reason, tc.logged)
			}
		})
	}
}

// stringer is a fmt.Stringer, the third kind of value replace checks.
type stringer string

func (s stringer) String() string { return string(s) }

// valueError and valueStringer have value receivers, so calling their method through a nil
// pointer panics; nilSafeError has a pointer receiver and handles nil itself.
type (
	valueError    struct{}
	valueStringer struct{}
	nilSafeError  struct{}
)

func (valueError) Error() string     { return "value error" }
func (valueStringer) String() string { return "value stringer" }
func (*nilSafeError) Error() string  { return "nil-safe error carrying " + token }

// brokenStringer panics on a non-nil value: a bug, which is logged as panicked, never re-raised.
type brokenStringer struct{}

func (brokenStringer) String() string { panic("broken String carrying " + token) }

// nilMapStringer panics when nil: only a nil pointer is <nil>, as in fmt, so a nil map is !PANIC.
type nilMapStringer map[string]int

func (m nilMapStringer) String() string { m["x"] = 1; return "unreachable" }

// An error or Stringer never panics the logger, and the line keeps its other attributes (#239).
// Like fmt and slog, a typed-nil pointer whose method panics is <nil>, and a nil-safe method still
// runs and is still redacted. Any other panicking method, even one on a nil map, is logged as !PANIC,
// without the panic's text: slog promises that for its own values, and a re-raised panic would kill a
// goroutine that has no recover.
func TestAnErrorOrStringerNeverPanicsTheLogger(t *testing.T) {
	for name, tc := range map[string]struct {
		value  any
		logged string
	}{
		"a nil error with a value receiver":         {value: (*valueError)(nil), logged: "<nil>"},
		"a nil Stringer with a value receiver":      {value: (*valueStringer)(nil), logged: "<nil>"},
		"a nil-safe error's text is still redacted": {value: (*nilSafeError)(nil), logged: redacted},
		"a panicking value":                         {value: brokenStringer{}, logged: "!PANIC"},
		"a panicking non-nil pointer":               {value: &brokenStringer{}, logged: "!PANIC"},
		"a panicking nil map":                       {value: nilMapStringer(nil), logged: "!PANIC"},
		"a joined typed-nil error":                  {value: errors.Join((*valueError)(nil)), logged: "!PANIC"},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, "json").Info("x", "reason", tc.value, "method", "POST")
			var line struct{ Reason, Method string }
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("log line %q: %v", buf.String(), err)
			}
			if line.Reason != tc.logged || line.Method != "POST" {
				t.Fatalf("logged reason %q and method %q, want %q and POST", line.Reason, line.Method, tc.logged)
			}
		})
	}
}

func TestGroupContentsAreDropped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "json").Info("x", slog.Group("req", "reason", "inside"))
	if strings.Contains(buf.String(), "inside") {
		t.Fatalf("group content logged: %s", buf.String())
	}
}

func TestTimeIsUTC(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "json").Info("x")
	var line struct{ Time string }
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339Nano, line.Time)
	if err != nil || ts.Location() != time.UTC {
		t.Fatalf("time %q not UTC: %v", line.Time, err)
	}
}

func TestTextFormatRedactsToo(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "text").Info("request", "reason", "Bearer "+token, "token", token)
	if strings.Contains(buf.String(), token) || !strings.Contains(buf.String(), redacted) {
		t.Fatalf("text log leaks: %s", buf.String())
	}
}

func TestMiddlewareLogsRequestWithoutQueryOrHeaders(t *testing.T) {
	var buf bytes.Buffer
	var seen string
	h := Middleware(New(&buf, "json"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
		w.WriteHeader(http.StatusTeapot)
	}))
	r := httptest.NewRequest("POST", "/mcp?access_token="+token, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Mcp-Method", "tools/call")
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	r.RemoteAddr = "192.0.2.7:51234"
	r.Header.Set("X-Request-Id", "spoofed")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	out := buf.String()
	if rec.Header().Get("X-Request-Id") != seen || strings.Contains(out, "spoofed") {
		t.Fatalf("request id not echoed or inbound id trusted: %q / %s", rec.Header().Get("X-Request-Id"), out)
	}
	if !uuidV4.MatchString(seen) || !strings.Contains(out, seen) {
		t.Fatalf("request id %q not logged: %s", seen, out)
	}
	if strings.Contains(out, token) || strings.Contains(out, "access_token") {
		t.Fatalf("log leaks: %s", out)
	}
	if !strings.Contains(out, `"remote_ip":"192.0.2.7"`) || strings.Contains(out, "6.6.6.6") {
		t.Fatalf("remote ip must be the TCP peer: %s", out)
	}
	if !strings.Contains(out, `"status":418`) || !strings.Contains(out, `"mcp_method":"tools/call"`) {
		t.Fatalf("missing fields: %s", out)
	}
}

// Every line logged with a request's context carries its ID exactly once, in both formats and
// through a logger with attributes, so no caller adds it by hand; a line without one carries none,
// and one that already names an ID keeps its own.
func TestALineCarriesItsRequestsID(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-1")
	for name, tc := range map[string]struct {
		format string
		log    func(*slog.Logger)
		want   []string // request_id values in the line, in order
		keeps  string   // another part of the line that must survive
	}{
		"a request's line":     {format: "json", log: func(l *slog.Logger) { l.InfoContext(ctx, "x") }, want: []string{"req-1"}},
		"through With":         {format: "json", log: func(l *slog.Logger) { l.With("upstream", "u").WarnContext(ctx, "x") }, want: []string{"req-1"}, keeps: `"upstream":"u"`},
		"an ID the logger has": {format: "json", log: func(l *slog.Logger) { l.With("request_id", "own").InfoContext(ctx, "x") }, want: []string{"own"}},
		"an ID the logger has, through a later With": {format: "json", log: func(l *slog.Logger) { l.With("request_id", "own").With("upstream", "u").InfoContext(ctx, "x") },
			want: []string{"own"}, keeps: `"upstream":"u"`},
		"through LogAttrs":     {format: "json", log: func(l *slog.Logger) { l.LogAttrs(ctx, slog.LevelError, "x") }, want: []string{"req-1"}},
		"no request":           {format: "json", log: func(l *slog.Logger) { l.InfoContext(context.Background(), "x") }},
		"no context":           {format: "json", log: func(l *slog.Logger) { l.Info("x") }},
		"an ID the caller set": {format: "json", log: func(l *slog.Logger) { l.InfoContext(ctx, "x", "request_id", "own") }, want: []string{"own"}},
		"the text format":      {format: "text", log: func(l *slog.Logger) { l.InfoContext(ctx, "x") }, want: []string{"req-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.log(New(&buf, tc.format))
			got := regexp.MustCompile(`"?request_id"?[:=]"?([^",\s]+)`).FindAllStringSubmatch(buf.String(), -1)
			var ids []string
			for _, m := range got {
				ids = append(ids, m[1])
			}
			if !slices.Equal(ids, tc.want) {
				t.Fatalf("request IDs %q, want %q: %s", ids, tc.want, buf.String())
			}
			if !strings.Contains(buf.String(), tc.keeps) {
				t.Fatalf("the line lost %s: %s", tc.keeps, buf.String())
			}
		})
	}
}

// The request line carries its ID whatever logger Middleware is given, not only New's, and once.
func TestTheRequestLineCarriesItsIDWithAnyLogger(t *testing.T) {
	for name, log := range map[string]func(*bytes.Buffer) *slog.Logger{
		"a plain slog logger": func(b *bytes.Buffer) *slog.Logger { return slog.New(slog.NewJSONHandler(b, nil)) },
		"New's logger":        func(b *bytes.Buffer) *slog.Logger { return New(b, "json") },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			rec := httptest.NewRecorder()
			Middleware(log(&buf), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
			want := `"request_id":"` + rec.Header().Get("X-Request-Id") + `"`
			if strings.Count(buf.String(), `"request_id"`) != 1 || !strings.Contains(buf.String(), want) {
				t.Fatalf("request line %s, want %s once", buf.String(), want)
			}
		})
	}
}

// The request line logs the final status, not an informational one: 1xx statuses from 100 to 199
// precede it, except 101 Switching Protocols, which is final, as any status from 200 up is. The first
// final status, or a body, fixes it, and a handler that writes neither gets 200. Metrics and server
// spans record the status Observe gives them, the same one.
func TestInformationalStatusIsNotLoggedAsFinal(t *testing.T) {
	const body = 0 // in writes: a body write instead of a status
	for _, c := range []struct {
		name   string
		writes []int // what the handler writes, in order: a status, or body
		want   int   // the final status the request line logs
	}{
		{"103 Early Hints, then 502", []int{http.StatusEarlyHints, http.StatusBadGateway}, http.StatusBadGateway},
		{"101 Switching Protocols is final; a later 500 is ignored", []int{http.StatusSwitchingProtocols, http.StatusInternalServerError}, http.StatusSwitchingProtocols},
		{"100, the lowest informational, then 404", []int{http.StatusContinue, http.StatusNotFound}, http.StatusNotFound},
		{"199, the highest informational, then 503", []int{199, http.StatusServiceUnavailable}, http.StatusServiceUnavailable},
		{"200 is final; a later 500 is ignored", []int{http.StatusOK, http.StatusInternalServerError}, http.StatusOK},
		{"a body first fixes 200; a later 500 is ignored", []int{body, http.StatusInternalServerError}, http.StatusOK},
		{"nothing written is 200", nil, http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, code := range c.writes {
					if code == body {
						_, _ = w.Write([]byte("x"))
						continue
					}
					w.WriteHeader(code)
				}
			})
			var buf bytes.Buffer
			Middleware(New(&buf, "json"), handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			if wantLine := fmt.Sprintf(`"status":%d,`, c.want); !strings.Contains(buf.String(), wantLine) {
				t.Errorf("request line %s; want %s", buf.String(), wantLine)
			}
			got := 0 // what metrics and spans record
			Observe(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), handler, func(status int, _ CutOff) { got = status })
			if got != c.want {
				t.Errorf("Observe recorded status %d, want %d", got, c.want)
			}
		})
	}
}

// Entra takes client-request-id only as a GUID (ADR-0021 §2), so request IDs are version 4 UUIDs.
var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestRequestIDsAreDistinctVersion4UUIDs(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newRequestID()
		if !uuidV4.MatchString(id) || seen[id] {
			t.Fatalf("request id %q is not a fresh version 4 UUID", id)
		}
		seen[id] = true
	}
}

// HoldsJWT is the JWT shape a value may be refused by: a JWT whose header starts a word, or whose
// payload follows a dot. It finds what LooksSecret's JWT rule finds, except an eyJ header inside a
// word, which only the redactor hides (#495).
func TestHoldsJWTFindsAJWTButNotAnEyJInsideAWord(t *testing.T) {
	for _, tc := range []struct {
		s           string
		holds, hide bool
	}{
		{token, true, true},
		{"Bearer " + token, true, true},
		{"--token=" + token, true, true},
		{"x" + "." + "eyJ" + "zdWIiOiJ4In0" + ".sig", true, true}, // a header that does not start eyJ
		{"heyJude.example", false, true},
		{"HoneyJar.example", false, true},
		{"app2eyJet.example", false, true},                      // a digit before eyJ is inside the word
		{"OKeyJar.example", false, true},                        // so is an upper-case letter
		{"ann.eyJones", false, true},                            // a dot before eyJ, but no dot after it
		{"eyJ" + "hbGciOiJFUzI1NiJ9" + "." + "eyJ", true, true}, // cut short after the header's dot
		{"Basic tier", false, true},
		{"dcr-Qm9eyJx_7k-eyJAbCdEfGh", false, false},
	} {
		if got := HoldsJWT(tc.s); got != tc.holds {
			t.Errorf("HoldsJWT(%q) = %v, want %v", tc.s, got, tc.holds)
		}
		if got := LooksSecret(tc.s); got != tc.hide {
			t.Errorf("LooksSecret(%q) = %v, want %v", tc.s, got, tc.hide)
		}
	}
}
