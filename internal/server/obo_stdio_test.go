package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// newStdioOBOEnv is newOBOEnv with the fake stdio upstream (legacy MCP) instead of an HTTP one.
func newStdioOBOEnv(t *testing.T, scopes string, opts ...fakeidp.Option) *oboEnv {
	t.Helper()
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{oboPublic + "/callback/entra"}}
	e := &oboEnv{fake: fakeidp.New(t, fakeidp.Entra, append([]fakeidp.Option{fakeidp.WithClient(app)}, opts...)...), logs: &syncBuffer{}}
	origProvider := newEntraProvider
	newEntraProvider = func(c entra.Config) (*entra.Provider, error) {
		c.Tenant, c.ClientID, c.ClientAuth, c.HTTPClient = e.fake.TenantID(), app.ID, idp.ClientSecret("s3cret"), e.fake.HTTPClient()
		return entra.New(c)
	}
	t.Cleanup(func() { newEntraProvider = origProvider })
	// Each process's token socket lives under the temporary directory, which a long TMPDIR would
	// push over the socket path limit (#307).
	short, err := os.MkdirTemp("/tmp", "bw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	t.Setenv("TMPDIR", short)
	settings := append(authEnv(t), "BYWARD_PUBLIC_URL="+oboPublic+"/mcp", "BYWARD_OBO_SCOPES="+scopes)
	cfg, _, err := config.Load([]string{"--", bin, "-mcp"}, settings, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logging.New(e.logs, "json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if s.closeUpstream != nil {
			_ = s.closeUpstream(ctx)
		}
		if s.closeStore != nil {
			_ = s.closeStore()
		}
	})
	e.proxy = s
	e.srv = httptest.NewServer(s.Public.Handler)
	t.Cleanup(e.srv.Close)
	return e
}

// #307: check --offline and doctor refuse a temporary directory too long for the token socket, as
// startup does; without On-Behalf-Of there is no socket to place.
func TestOfflineChecksRefuseATempDirTooLongForTheTokenSocketWithOnBehalfOf(t *testing.T) {
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	load := func(extra ...string) *config.Config {
		cfg, _, err := config.Load([]string{"--", bin, "-mcp"}, append(authEnv(t), append(extra, "BYWARD_PUBLIC_URL="+oboPublic+"/mcp")...), os.ReadFile)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	obo, plain := load("BYWARD_OBO_SCOPES="+graphUserRead), load()
	t.Setenv("TMPDIR", "/"+strings.Repeat("d", 120)) // after the configs: t.TempDir reads it too
	if err := checkUpstream(obo); err == nil || !strings.Contains(err.Error(), "TMPDIR") {
		t.Fatalf("with On-Behalf-Of: %v, want an error naming TMPDIR", err)
	}
	if err := checkUpstream(plain); err != nil {
		t.Fatalf("without On-Behalf-Of: %v, want none", err)
	}
}

// initialize starts a legacy MCP session with the access token and returns its ID.
func (e *oboEnv) initialize(t *testing.T, access string) string {
	t.Helper()
	res := e.send(t, http.DefaultClient, "POST", "/mcp", strings.NewReader(initializeBody), http.Header{"Authorization": {"Bearer " + access},
		"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}})
	body := readAll(t, res)
	if res.StatusCode != http.StatusOK || res.Header.Get(mcpsession.Header) == "" {
		t.Fatalf("initialize: %d %s", res.StatusCode, body)
	}
	return res.Header.Get(mcpsession.Header)
}

// sessionResult is the JSON-RPC result string of the one SSE event in body.
func sessionResult(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "data: ")
	if i < 0 {
		t.Fatalf("no SSE event in %q", body)
	}
	data, _, _ := strings.Cut(body[i+len("data: "):], "\n")
	var msg struct{ Result string }
	if json.Unmarshal([]byte(data), &msg) != nil {
		t.Fatalf("no JSON-RPC result string in %q", body)
	}
	return msg.Result
}

// #141 end to end: the stdio process asks its token socket and gets a Microsoft Graph token On
// Behalf Of the signed-in user, from the same exchange as an HTTP upstream's.
func TestAStdioProcessGetsAGraphTokenOnBehalfOfItsUser(t *testing.T) {
	e := newStdioOBOEnv(t, graphUserRead)
	access := e.signIn(t)["access_token"].(string)
	session := e.initialize(t, access)
	status, body := e.mcp(t, access, `{"jsonrpc":"2.0","id":2,"method":"token"}`, http.Header{mcpsession.Header: {session}})
	var answer struct {
		AccessToken string `json:"access_token"`
		Error       string
	}
	if status != http.StatusOK || json.Unmarshal([]byte(sessionResult(t, body)), &answer) != nil || answer.AccessToken == "" {
		t.Fatalf("the process's ask got %d %s, want a token", status, body)
	}
	if claims := jwtClaims(t, answer.AccessToken); claims["aud"] != fakeidp.GraphAppID || claims["scp"] != "User.Read" {
		t.Fatalf("token claims %v, want a Graph token for User.Read", claims)
	}
	if logs := e.logs.String(); strings.Contains(logs, answer.AccessToken) || strings.Contains(logs, access) {
		t.Error("a token reached the log")
	}
}

// A request whose user has no downstream token is answered in the proxy's name before any process
// starts, as for an HTTP upstream (ADR-0017 §5, ADR-0025).
func TestAStdioRequestWithoutADownstreamTokenIsAnsweredBeforeAnyProcessStarts(t *testing.T) {
	e := newStdioOBOEnv(t, graphUserRead)
	access := e.signIn(t)["access_token"].(string)
	e.fake.Set(fakeidp.FailToken(fakeidp.GrantJWTBearer, &fakeidp.ConsentRequired))
	status, body := e.mcp(t, access, initializeBody, nil)
	var answer struct {
		Error struct {
			Data struct{ Downstream string }
		}
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &answer) != nil || answer.Error.Data.Downstream != "consent_required" {
		t.Fatalf("initialize got %d %s, want the proxy's consent_required answer", status, body)
	}
	if !strings.Contains(e.metrics(), "byward_stdio_processes 0") {
		t.Fatal("a process started for a request refused for want of a downstream token")
	}
	if _, ok := auditRecord(e.logs.String(), "downstream_token_refused"); !ok {
		t.Fatal("no downstream_token_refused audit record")
	}
}
