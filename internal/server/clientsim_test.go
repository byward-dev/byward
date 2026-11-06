package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/clientsim"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/go-jose/go-jose/v4"
)

// The client simulator (ADR-0024 §2): each closed client's profile signs in against the wired proxy
// the way that client does, then uses the MCP endpoint, so a change the client would not survive
// fails here instead of at release.
func TestClosedClientsSignInAndWorkAsTheirProfilesSay(t *testing.T) {
	for _, p := range clientsim.All {
		t.Run(p.Cell, func(t *testing.T) {
			e := newSimProxy(t, p)
			s := clientsim.SignIn(t, e, p)

			res := clientsim.Call(t, e, s, "")
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("initialize after sign-in: %d", res.StatusCode)
			}
			clientsim.WantNoAuthLoop(t, p, res)

			// ADR-0025: an upstream that refuses the proxy must not look like an auth failure.
			refused := clientsim.Call(t, e, s, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x","arguments":{}}}`)
			body, _ := io.ReadAll(refused.Body)
			_ = refused.Body.Close()
			clientsim.WantNoAuthLoop(t, p, refused)
			if refused.StatusCode != http.StatusOK || !strings.Contains(string(body), `"isError":true`) {
				t.Fatalf("a refused tools/call: %d %s; want a 200 tool error (ADR-0025)", refused.StatusCode, body)
			}

			// A token the proxy no longer accepts gets a 401 with the challenge: what makes the client
			// sign in again, or Claude Code rerun its headersHelper.
			stale := clientsim.Call(t, e, clientsim.Session{AccessToken: "byw_at_no-longer-valid"}, "")
			_ = stale.Body.Close()
			if stale.StatusCode != http.StatusUnauthorized || !strings.Contains(stale.Header.Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("an unusable token: %d %q; want a 401 challenge the client recovers from", stale.StatusCode, stale.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

// newSimProxy wires the proxy with the fake Entra, the clients' published CIMD documents, a static
// client for profiles that use one, and an upstream that refuses tools/call with 403.
func newSimProxy(t *testing.T, p clientsim.Profile) clientsim.Env {
	t.Helper()
	const public = "https://mcp.example.com"
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/entra"}}
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithClient(app))

	var docs []clientdocs.Doc
	var auth idp.ClientAuth
	clientID := p.ClientID
	if p.Registration == clientsim.CIMD {
		doc := clientdocs.Load(t, p.ClientID)
		docs, clientID = append(docs, doc), doc.ClientID
		if p.PrivateKeyJWT { // only the client holds its private key: serve a test key at the document's jwks_uri
			var published struct {
				JWKSURI string `json:"jwks_uri"`
			}
			if err := json.Unmarshal(doc.Body, &published); err != nil || published.JWKSURI == "" {
				t.Fatalf("%s's document has no jwks_uri: %v", p.Client, err)
			}
			cert := fakeidp.NewCertificate(t)
			jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &cert.Key.PublicKey, KeyID: "sim", Algorithm: "RS256", Use: "sig"}}})
			if err != nil {
				t.Fatal(err)
			}
			docs = append(docs, clientdocs.Doc{ClientID: published.JWKSURI, Body: jwks, Header: http.Header{"Content-Type": {"application/json"}}})
			if auth, err = idp.PrivateKeyJWT(cert.Key, cert.X509, "sim"); err != nil {
				t.Fatal(err)
			}
		}
	}
	served := clientdocs.Serve(t, docs...)
	origReg, origBroker := newCIMDRegistry, newBroker
	t.Cleanup(func() { newCIMDRegistry, newBroker = origReg, origBroker })
	newCIMDRegistry = func(c registration.CIMDConfig) *registration.CIMDRegistry {
		guard := ssrfguard.New(ssrfguard.Config{RootCAs: served.RootCAs, Dial: served.Dial})
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

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"tools/call"`) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(up.Close)
	env := append(authEnv(t), "BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp")
	if p.Registration == clientsim.Static {
		clients := filepath.Join(t.TempDir(), "clients.json")
		if err := os.WriteFile(clients, []byte(`{"clients":[{"client_id":"`+p.ClientID+`","client_name":"`+p.Client+
			`","token_endpoint_auth_method":"none","redirect_uris":["http://localhost/callback"]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		env = append(env, "BYWARD_STATIC_CLIENTS_FILE="+clients)
	}
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	srv := httptest.NewServer(Handler(cfg, discard, a.validator, a.register, a.sessions, Observability{}))
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "http://")
	return clientsim.Env{
		Public: public, MCPPath: "/mcp", ClientID: clientID, ConsentDelay: broker.ConsentDelay, ClientAuth: auth,
		Do: func(r *http.Request) (*http.Response, error) {
			r = r.Clone(context.Background())
			r.URL.Scheme, r.URL.Host, r.Host = "http", target, "mcp.example.com"
			return http.DefaultTransport.RoundTrip(r)
		},
		Browser: func(location string) (*http.Response, error) { return fake.HTTPClient().Get(location) },
	}
}
