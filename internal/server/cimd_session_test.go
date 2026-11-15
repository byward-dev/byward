package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

// The wiring end to end: a CIMD client (claude.ai's published document) signs a user in through the
// wired broker, and its access token then drives a legacy MCP session that the wired session
// binding seals to that user.
func TestACIMDClientSignsInAndUsesALegacySession(t *testing.T) {
	const public = "https://mcp.example.com"
	doc := clientdocs.Load(t, "claude-ai")
	docs := clientdocs.Serve(t, doc)
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/entra"}}
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app))

	serveCIMDFrom(t, docs)
	useFakeEntra(t, fake, app)

	up := fakeupstream.New()
	up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(mcpsession.Header, "upstream-session-1")
		w.WriteHeader(http.StatusOK)
	}
	t.Cleanup(up.Close)
	cfg := loadConfig(t, public+"/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp")
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	srv := httptest.NewServer(Handler(cfg, discard, httpUpstream(cfg, discard), a.validator, a.register, a.sessions, Observability{}))
	t.Cleanup(srv.Close)

	b := newTestBrowser(t, srv.URL, public)
	send := b.send

	q := authorizeQuery(url.Values{"client_id": {doc.ClientID}, "redirect_uri": {doc.Redirect}, "state": {"s"}, "scope": {"mcp"}})
	page := send(http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
	body := readAll(t, page)
	if page.StatusCode != http.StatusOK || !strings.Contains(body, "Published by") {
		t.Fatalf("consent page: %d %s", page.StatusCode, body)
	}
	allow := b.allow(page, body)
	if allow.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent answer: %d %s", allow.StatusCode, readAll(t, allow))
	}
	idpRes, err := fake.HTTPClient().Get(allow.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	back := send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, allow.Cookies())
	ret, _ := url.Parse(back.Header.Get("Location"))
	if back.StatusCode != http.StatusFound || !strings.HasPrefix(ret.String(), doc.Redirect) {
		t.Fatalf("callback: %d, Location %q", back.StatusCode, back.Header.Get("Location"))
	}
	if docs.Hits(doc.ClientID) == 0 {
		t.Fatal("the sign-in never fetched the client document from the local docs server")
	}
	tok := send(http.MethodPost, "/token", url.Values{"grant_type": {"authorization_code"}, "code": {ret.Query().Get("code")},
		"client_id": {doc.ClientID}, "redirect_uri": {doc.Redirect}, "code_verifier": {testVerifier}}, nil)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tok.Body).Decode(&tokens); err != nil || tok.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("token: %d %v", tok.StatusCode, err)
	}

	mcp := func(session string) *http.Response {
		h := http.Header{"Authorization": {"Bearer " + tokens.AccessToken}, "Content-Type": {"application/json"},
			"Accept": {"application/json, text/event-stream"}}
		if session != "" {
			h.Set(mcpsession.Header, session)
		}
		r, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		r.Host = "mcp.example.com"
		r.Header = h
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	first := mcp("")
	id := first.Header.Get(mcpsession.Header)
	if first.StatusCode != http.StatusOK || !strings.HasPrefix(id, mcpsession.Prefix) {
		t.Fatalf("first MCP call: %d, session %q; want a sealed session ID", first.StatusCode, id)
	}
	next := mcp(id)
	if last, _ := up.Last(); next.StatusCode != http.StatusOK || last.Header.Get(mcpsession.Header) != "upstream-session-1" {
		t.Fatalf("the CIMD user's next call: %d, upstream saw %q", next.StatusCode, last.Header.Get(mcpsession.Header))
	}
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
