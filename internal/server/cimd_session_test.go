package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
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

	origReg, origBroker := newCIMDRegistry, newBroker
	t.Cleanup(func() { newCIMDRegistry, newBroker = origReg, origBroker })
	newCIMDRegistry = func(c registration.CIMDConfig) *registration.CIMDRegistry {
		guard := ssrfguard.New(ssrfguard.Config{RootCAs: docs.RootCAs, Dial: docs.Dial})
		c.Fetch, c.KeysClient = guard, guard.HTTPClient()
		return origReg(c)
	}
	newBroker = func(c broker.Config) (*broker.Broker, error) {
		prov, err := entra.New(entra.Config{Tenant: fake.TenantID(), ClientID: app.ID, ClientAuth: idp.ClientSecret("s3cret"),
			RedirectURL: public + "/callback/entra", HTTPClient: fake.HTTPClient()})
		if err != nil {
			return nil, err
		}
		c.IdP, c.IdPScopes = prov, prov.Scope()
		return origBroker(c)
	}

	var upstreamSessions []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSessions = append(upstreamSessions, r.Header.Get(mcpsession.Header))
		w.Header().Set(mcpsession.Header, "upstream-session-1")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	srv := httptest.NewServer(Handler(cfg, discard, httpUpstream(cfg, discard), a.validator, a.register, a.sessions, Observability{}))
	t.Cleanup(srv.Close)

	b := newTestBrowser(t, srv.URL, public)
	send := b.send

	verifier := "verifier-0123456789-0123456789-0123456789-abc"
	q := url.Values{"client_id": {doc.ClientID}, "redirect_uri": {doc.Redirect}, "response_type": {"code"}, "state": {"s"},
		"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}, "scope": {"mcp"}}
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
	tok := send(http.MethodPost, "/token", url.Values{"grant_type": {"authorization_code"}, "code": {ret.Query().Get("code")},
		"client_id": {doc.ClientID}, "redirect_uri": {doc.Redirect}, "code_verifier": {verifier}}, nil)
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
	if next := mcp(id); next.StatusCode != http.StatusOK || upstreamSessions[len(upstreamSessions)-1] != "upstream-session-1" {
		t.Fatalf("the CIMD user's next call: %d, upstream saw %q", next.StatusCode, upstreamSessions[len(upstreamSessions)-1])
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

// pkce is the S256 code challenge for verifier (RFC 7636 §4.2).
func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
