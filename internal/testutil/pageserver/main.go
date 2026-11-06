// Command pageserver serves the broker's consent and error pages with a stub IdP and fixed
// clients, on loopback http, for the browser lane (scripts/ui): Playwright and axe check the pages
// as a browser renders them, and the run saves screenshots for review. Test-only; never shipped.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/corker/mcp-authproxy/internal/broker"
	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/store/memory"
	"github.com/corker/mcp-authproxy/internal/token"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9440", "loopback address")
	flag.Parse()
	if err := run(*addr); err != nil {
		fmt.Fprintln(os.Stderr, "pageserver:", err)
		os.Exit(1)
	}
}

func run(addr string) error {
	origin := "http://" + addr
	dir, err := os.MkdirTemp("", "pageserver")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	k := make([]byte, token.KeySize)
	_, _ = rand.Read(k)
	if err := os.WriteFile(filepath.Join(dir, "k1"), []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		return err
	}
	ring, err := token.LoadKeyRing(dir)
	if err != nil {
		return err
	}
	resource, _ := url.Parse(origin + "/mcp")
	sealer, err := token.NewSealer(ring, resource.String())
	if err != nil {
		return err
	}
	clock := &clock{now: time.Now()}
	box := func(purpose string) *token.Box { b, _ := token.NewBox(ring, purpose, clock.Now); return b }
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	b, err := broker.New(broker.Config{Issuer: origin, Origin: origin, Resource: resource, Scope: "mcp", IdPName: "entra",
		IdPLabel: "Microsoft Entra", IdPScopes: "openid profile email offline_access api://00000000-0000-0000-0000-000000000001/access_as_user",
		IdP: stubIdP{origin: origin}, Clients: clients{}, Store: memory.New(), Sealer: sealer, LoginBox: box("login"),
		IdPTokenBox: box("idp-tokens"), ConsentBox: box("consent"), UpstreamName: "Team dashboards",
		ScopeText: "Read and query your team's dashboards.", OperatorName: "Contoso IT", Log: log, Now: clock.Now})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	b.Register(mux)
	// The browser lane moves time forward here instead of sleeping (POST /test/advance?d=1s).
	mux.HandleFunc("POST /test/advance", clock.advance)
	srv := &http.Server{Addr: addr, Handler: logging.Middleware(log, mux), ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

// clock is the broker's time, moved only by the tests.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(w http.ResponseWriter, r *http.Request) {
	d, err := time.ParseDuration(r.URL.Query().Get("d"))
	if err != nil || d <= 0 {
		http.Error(w, "want d, a positive duration", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// stubIdP sends the browser to a local page; the browser lane stops there.
type stubIdP struct{ origin string }

func (s stubIdP) AuthCodeURL(_ context.Context, l idp.Login) (string, error) {
	return s.origin + "/stub-idp?state=" + url.QueryEscape(l.State), nil
}

func (stubIdP) Callback(context.Context, url.Values, idp.Login) (idp.Identity, idp.Tokens, error) {
	return idp.Identity{}, idp.Tokens{}, errors.New("stub IdP: no callback")
}

func (stubIdP) Refresh(context.Context, string) (*idp.Identity, idp.Tokens, error) {
	return nil, idp.Tokens{}, errors.New("stub IdP: no refresh")
}

// clients: a loopback app (Claude Code-like), an https web app, and an unverified one whose name
// carries control and bidi characters.
type clients struct{}

func (clients) Client(_ context.Context, id string) (registration.Client, error) {
	switch id {
	case "desktop":
		return client{id: id, name: "Example Desktop App", trust: registration.Verified, redirect: "http://127.0.0.1:43210/callback"}, nil
	case "web":
		return client{id: id, name: "Example Web App", trust: registration.Domain, redirect: "https://app.example.org/oauth/callback"}, nil
	case "long":
		return client{id: id, name: strings.Repeat("Averyveryverylongappname", 4), trust: registration.Domain,
			redirect: "https://a-very-long-subdomain-name-for-reflow-checks.app.example.org/oauth/callback"}, nil
	case "unverified":
		return client{id: id, name: "Free \u202eTools\x1b[0m Helper", trust: registration.NotVerified, redirect: "http://127.0.0.1:43210/callback"}, nil
	}
	return nil, registration.ErrUnknownClient
}

type client struct {
	id, name, redirect string
	trust              registration.TrustLevel
}

func (c client) ID() string                        { return c.id }
func (c client) Name() string                      { return c.name }
func (c client) Trust() registration.TrustLevel    { return c.trust }
func (client) AuthMethod() registration.AuthMethod { return registration.None }
func (c client) RedirectAllowed(u string) error {
	if u != c.redirect {
		return errors.New("registered " + c.redirect + ", sent " + u)
	}
	return nil
}
func (client) Authenticate(context.Context, url.Values, http.Header, string, time.Time) error {
	return errors.New("stub client: no token endpoint")
}
