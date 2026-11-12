package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
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
		"a client ID with eyJ":                                    {value: "dcr-Qm9eyJx_7k-eyJAbCdEfGh", logged: "dcr-Qm9eyJx_7k-eyJAbCdEfGh"},
		"a client ID with eyj":                                    {value: "dcr-xeyjq0Z-eyjAbCdEfGhIjk", logged: "dcr-xeyjq0Z-eyjAbCdEfGhIjk"},
		"a URL with eyJ and one dot":                              {value: "https://heyJude.example/cb", logged: "https://heyJude.example/cb"},
		"a URL with .eyJ and one dot":                             {value: "https://app.eyJude/cb", logged: "https://app.eyJude/cb"},
		"a host label starting with eyj":                          {value: "https://app.eyjude.example.com/cb", logged: "https://app.eyjude.example.com/cb"},
		"a host with eyj and two dots":                            {value: "https://heyjude.example.com/cb", logged: "https://heyjude.example.com/cb"},
		"a bare JWT":                                              {value: token, logged: redacted},
		"a JWT with _ and - in it":                                {value: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE_Yj5jIn0.eyJzdWIiOiJ4Pz5-In0.c2ln", logged: redacted},
		"an unsigned JWT":                                         {value: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", logged: redacted},
		"a JWT cut before its signature":                          {value: "stderr: token=eyJhbGciOiJSUzI1NiJ9.eyJ1cG4iOiJh", logged: redacted},
		"a JWT whose header has a space":                          {value: "token eyAiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ4Pz5-In0.c2ln rejected", logged: redacted},
		"a JWE cut after its encrypted key":                       {value: "stderr: token=eyJhbGciOiJSU0EtT0FFUCJ9.ZW5j_cnl-dGVk", logged: redacted},
		"a spaced-header JWT cut short":                           {value: "stderr: token=eyAiYWxnIjoiUlMyNTYiLCJraWQiOiJrMCJ9.eyJzdWIiOiJ4", logged: redacted},
		"a spaced-header JWT with _ and - cut short":              {value: "stderr: token=eyAiYWxnIjoiUlMyNTYiQ-.eyJzdWIi_x", logged: redacted},
		"a JWE whose header has a -":                              {value: "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6Ij8-In0.ZW5j.aXY.Y3Q.dGFn", logged: redacted},
		"a spaced header ending in a lowercase letter, cut short": {value: "stderr: token=eyAiYWxnIjoiUlMyNTYifz.eyJzdWIiOiJ4", logged: redacted},
		"a spaced header ending in _, cut short":                  {value: "stderr: token=eyAiYWxnIjoiUlMyNTYiI_.eyJzdWIiOiJ4", logged: redacted},
		"a JWE with no encrypted key":                             {value: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiYT9iPmMifQ_..aXY.Y3Q.dGFn", logged: redacted},
		"a Bearer value":                                          {value: "Bearer opaque-token", logged: redacted},
		"a lowercase bearer value":                                {value: "authorization: bearer opaque-token", logged: redacted},
		"a lowercase basic value":                                 {value: "authorization: basic dXNlcjpwdw==", logged: redacted},
		"a Basic value":                                           {value: "Basic dXNlcjpwdw==", logged: redacted},
		"an uppercase BASIC value":                                {value: "BASIC dXNlcjpwdw==", logged: redacted},
		"a tab between Bearer and its token":                      {value: "authorization: Bearer\topaque-token", logged: redacted},
		"a config error that names client_secret_basic":           {value: "client_secret_file: only with client_secret_basic or client_secret_post", logged: "client_secret_file: only with client_secret_basic or client_secret_post"},
		"a Bearer value after a quote":                            {value: `upstream said "Bearer opaque-token"`, logged: redacted},
		"three spaces between Bearer and its token":               {value: "Bearer   opaque-token", logged: redacted},
		"a Basic credential that starts with +":                   {value: "Basic +dXNlcjpwdw==", logged: redacted},
		"a field named bearer_token":                              {value: "missing field bearer_token in the request", logged: "missing field bearer_token in the request"},
		"a Bearer value after a JSON escape":                      {value: `{"msg":"retrying with\nBearer byw_at_opaque"}`, logged: redacted},
		"a Basic value after an escaped CRLF":                     {value: `b'GET / HTTP/1.1\r\nBasic YTpi'`, logged: redacted},
		"a Bearer value after a URL-encoded space":                {value: "Authorization=%20Bearer opaque-token", logged: redacted},
		"prose that names a scheme, an accepted over-redaction":   {value: "the upstream wants basic auth", logged: redacted},
		"a Bearer value inside a message":                         {value: "upstream rejected Bearer opaque-token as expired", logged: redacted},
		"a Bearer value inside an error":                          {value: errors.New("upstream echoed Authorization: Bearer opaque-token"), logged: redacted},
		"a Bearer value after a colon":                            {value: "authorization:Bearer opaque-token", logged: redacted},
		"a Bearer token that starts with _":                       {value: "Bearer _opaque-token", logged: redacted},
		"a Bearer value in a Go header map":                       {value: "headers map[Authorization:[Bearer opaque-token]]", logged: redacted},
		"a quoted Bearer value at the start":                      {value: "'Bearer opaque-token'", logged: redacted},
		"a Bearer token that starts with -":                       {value: "Bearer -pAqUe7oKen", logged: redacted},
		"a Bearer token that starts with /":                       {value: "Bearer /pAqUe7oKen", logged: redacted},
		"a name that ends in _bearer":                             {value: "unknown kind x_bearer in config", logged: "unknown kind x_bearer in config"},
		"a short Basic credential":                                {value: "Basic YTpi", logged: redacted},
		"a scheme with no credential after it":                    {value: "the Authorization header had only Bearer ", logged: "the Authorization header had only Bearer "},
		"a JWT inside a message":                                  {value: "upstream rejected " + token + " as expired", logged: redacted},
		"a JWT inside an error":                                   {value: errors.New("verify " + token + ": expired"), logged: redacted},
		"a Stringer with a JWT":                                   {value: stringer("verify " + token), logged: redacted},
		"an error with an eyJ identifier":                         {value: errors.New("unknown client dcr-eyJq0Z"), logged: "unknown client dcr-eyJq0Z"},
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

func TestInformationalStatusIsNotLoggedAsFinal(t *testing.T) {
	var buf bytes.Buffer
	h := Middleware(New(&buf, "json"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(buf.String(), `"status":502`) {
		t.Fatalf("logged %s", buf.String())
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
