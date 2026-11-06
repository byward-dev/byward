// Package clientdocs holds the Client ID Metadata Documents real MCP clients publish (testdata,
// captured 2026-11-06) and an HTTPS server that serves them under their real host names, for tests
// of CIMD support. Fixtures only, never presets in code (ADR-0009 §9).
package clientdocs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

//go:embed testdata/*.json testdata/*.headers testdata/dcr/*.json
var files embed.FS

// Doc is one published document.
type Doc struct {
	Name     string // fixture name: claude-code, claude-ai, vscode, chatgpt
	ClientID string // the document's URL, which is its client_id
	Body     []byte
	Header   http.Header // Cache-Control and Content-Type as served
	// Redirect is a redirect URI the document accepts, as the client sends it: Claude Code
	// registers loopback without a port, VS Code with port 33418, so both use another port here.
	Redirect string
}

// redirects are the fixtures and a redirect URI each accepts.
var redirects = map[string]string{
	"claude-code": "http://127.0.0.1:53111/callback",
	"claude-ai":   "https://claude.ai/api/mcp/auth_callback",
	"vscode":      "http://127.0.0.1:40123/",
	"chatgpt":     "https://chatgpt.com/connector_platform_oauth_redirect",
}

// Names lists the fixtures.
var Names = []string{"claude-code", "claude-ai", "vscode", "chatgpt"}

// Load returns a fixture.
func Load(t testing.TB, name string) Doc {
	t.Helper()
	body, err := files.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	raw, err := files.ReadFile("testdata/" + name + ".headers")
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			h.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return Doc{Name: name, ClientID: d.ClientID, Body: body, Header: h, Redirect: redirects[name]}
}

// Server serves documents at their client_id URLs over HTTPS, whatever host the URL names: Dial
// connects every address to it and RootCAs trusts its certificate (the ssrfguard test hooks).
type Server struct {
	RootCAs *x509.CertPool

	addr string
	mu   sync.Mutex
	docs map[string]Doc // by client_id
	hits map[string]int
}

// Serve starts a server for docs, with a certificate for each document's host.
func Serve(t testing.TB, docs ...Doc) *Server {
	t.Helper()
	s := &Server{docs: map[string]Doc{}, hits: map[string]int{}}
	var hosts []string
	for _, d := range docs {
		s.docs[d.ClientID] = d
		u, _ := url.Parse(d.ClientID)
		hosts = append(hosts, u.Hostname())
	}
	cert, pool := certificate(t, hosts)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.addr, s.RootCAs = srv.Listener.Addr().String(), pool
	return s
}

// Dial connects any address to the server.
func (s *Server) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, s.addr)
}

// Hits counts the fetches of a client_id URL.
func (s *Server) Hits(clientID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[clientID]
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	id := "https://" + r.Host + r.URL.RequestURI()
	s.mu.Lock()
	d, ok := s.docs[id]
	s.hits[id]++
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	for k, v := range d.Header {
		w.Header()[k] = v
	}
	_, _ = w.Write(d.Body)
}

func certificate(t testing.TB, hosts []string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "clientdocs"}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// Registration is a real client's dynamic registration request (RFC 7591), with a redirect URI the
// broker keeps and the ones it drops because they fail the redirect policy (ADR-0009).
type Registration struct {
	Name     string
	Body     []byte
	Redirect string
	Dropped  []string
}

// Registrations lists the registration fixtures, sorted.
var Registrations = slices.Sorted(maps.Keys(registrationRedirects))

// registrationRedirects is, per fixture in testdata/dcr, the redirect URI to sign in with and the
// URIs the redirect policy drops.
var registrationRedirects = map[string]struct {
	redirect string
	dropped  []string
}{
	"gemini-cli":    {redirect: "http://localhost:52341/oauth/callback"},
	"mcp-inspector": {redirect: "http://127.0.0.1:6276/oauth/callback"},
	"cursor":        {redirect: "https://www.cursor.com/agents/mcp/oauth/callback", dropped: []string{"cursor://anysphere.cursor-mcp/oauth/callback"}},
}

// LoadRegistration returns a registration fixture.
func LoadRegistration(t testing.TB, name string) Registration {
	t.Helper()
	body, err := files.ReadFile("testdata/dcr/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := registrationRedirects[name]
	if !ok {
		t.Fatalf("clientdocs: no registration fixture %q (add it to registrationRedirects)", name)
	}
	return Registration{Name: name, Body: body, Redirect: r.redirect, Dropped: r.dropped}
}
