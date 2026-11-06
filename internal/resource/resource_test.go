package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func meta() Metadata {
	u, _ := url.Parse("https://mcp.example.com/mcp")
	return Metadata{Resource: u, Issuer: "https://mcp.example.com", Scope: "mcp", Name: "Example"}
}

type fakeValidator map[string]error

func (f fakeValidator) Validate(_ context.Context, tok string) (Identity, error) {
	if err, ok := f[tok]; ok {
		return Identity{}, err
	}
	return Identity{Subject: "tid:oid"}, nil
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMetadataDocument(t *testing.T) {
	m := meta()
	if got := m.PathInsertedURL(); got != "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("path-inserted URL = %q", got)
	}
	w := serve(MetadataHandler(m), httptest.NewRequest("GET", m.Paths()[0], nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "max-age=3600" {
		t.Fatalf("code=%d headers=%v", w.Code, w.Header())
	}
	var d map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d["resource"] != "https://mcp.example.com/mcp" || d["authorization_servers"].([]any)[0] != "https://mcp.example.com" ||
		d["bearer_methods_supported"].([]any)[0] != "header" || d["scopes_supported"].([]any)[0] != "mcp" || d["resource_name"] != "Example" {
		t.Fatalf("doc = %v", d)
	}
	if _, ok := d["resource_documentation"]; ok {
		t.Fatal("empty documentation should be omitted")
	}
}

func TestMetadataCORS(t *testing.T) {
	r := httptest.NewRequest("OPTIONS", WellKnownPath, nil)
	r.Header.Set("Origin", "https://app.example")
	w := serve(MetadataHandler(meta()), r)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
		t.Fatalf("code=%d headers=%v", w.Code, w.Header())
	}
	if w := serve(MetadataHandler(meta()), httptest.NewRequest("POST", WellKnownPath, nil)); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST got %d", w.Code)
	}
}

var reached = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	w.Header().Set("X-Subject", id.Subject)
	w.Header().Set("X-Query", r.URL.RawQuery)
	w.WriteHeader(http.StatusNoContent)
})

const challenge = `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp"`

func TestGuardMissingToken(t *testing.T) {
	g := Guard(meta(), fakeValidator{}, reached)
	for _, auth := range []string{"", "Basic dXNlcjpwYXNz", "Bearer ", "Bearer"} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := serve(g, r)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != challenge {
			t.Fatalf("auth %q: code=%d www=%q", auth, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestGuardBadTokens(t *testing.T) {
	g := Guard(meta(), fakeValidator{"tok-exp-1": ErrExpired, "tok-bad-2": ErrInvalid, "tok-err-3": context.DeadlineExceeded}, reached)
	cases := map[string]string{"tok-exp-1": descExpired, "tok-bad-2": descInvalid, "tok-err-3": descInvalid}
	for tok, desc := range cases {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header.Set("Authorization", "bearer "+tok)
		w := serve(g, r)
		want := challenge + `, error="invalid_token", error_description="` + desc + `"`
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: code=%d www=%q", tok, w.Code, w.Header().Get("WWW-Authenticate"))
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] != "invalid_token" || body["error_description"] != desc {
			t.Fatalf("%s: body %s", tok, w.Body)
		}
		if strings.Contains(w.Body.String(), tok) {
			t.Fatalf("%s: token echoed", tok)
		}
	}
}

func TestGuardValidTokenReachesNextWithIdentity(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp?x=1&access_token=q", nil)
	w := serve(Guard(meta(), fakeValidator{}, reached), r)
	if w.Code != 401 {
		t.Fatalf("query token must be ignored, got %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/mcp?x=1", nil)
	r.Header.Set("Authorization", "Bearer good")
	w = serve(Guard(meta(), fakeValidator{}, reached), r)
	if w.Code != http.StatusNoContent || w.Header().Get("X-Subject") != "tid:oid" || w.Header().Get("X-Query") != "x=1" {
		t.Fatalf("code=%d headers=%v", w.Code, w.Header())
	}
}

func TestGuardTokenSentTwice(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp?access_token=q", nil)
	r.Header.Set("Authorization", "Bearer good")
	if w := serve(Guard(meta(), fakeValidator{}, reached), r); w.Code != 400 {
		t.Fatalf("got %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Add("Authorization", "Bearer a")
	r.Header.Add("Authorization", "Bearer b")
	if w := serve(Guard(meta(), fakeValidator{}, reached), r); w.Code != 400 {
		t.Fatalf("two headers: got %d", w.Code)
	}
}

func TestNoTokensRejectsEverything(t *testing.T) {
	if _, err := (NoTokens{}).Validate(context.Background(), "anything"); err != ErrInvalid {
		t.Fatal(err)
	}
}
