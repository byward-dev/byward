package doctor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// proxy is a stand-in for the proxy's discovery; each field breaks one thing.
type proxy struct {
	resource       string // "" serves the target's resource
	issuer         string // "" serves the target's issuer
	noIssParameter bool
	misdirect      bool // 421 on everything
	redirectRoot   bool // the root resource metadata redirects
	noChallenge    bool // the 401 has no WWW-Authenticate
	challengeURL   string
	openMCP        bool // the MCP endpoint answers 200 without a token
	hugeMetadata   bool
	noRevocation   bool
	noS256         bool
	htmlMetadata   bool // every metadata document is an HTML page, as a misrouted ingress serves
}

func (p proxy) handler(origin string) http.Handler {
	resource, issuer := origin+"/mcp", origin
	if p.resource != "" {
		resource = p.resource
	}
	if p.issuer != "" {
		issuer = p.issuer
	}
	prm := func(w http.ResponseWriter, r *http.Request) {
		if p.htmlMetadata {
			_, _ = w.Write([]byte("<html>login</html>"))
			return
		}
		if p.hugeMetadata {
			_, _ = w.Write([]byte(`{"resource":"` + strings.Repeat("x", maxMetadata) + `"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{issuer}})
	}
	asm := func(w http.ResponseWriter, r *http.Request) {
		if p.htmlMetadata {
			_, _ = w.Write([]byte("<html>login</html>"))
			return
		}
		doc := map[string]any{"issuer": issuer, "authorization_response_iss_parameter_supported": !p.noIssParameter,
			"code_challenge_methods_supported": []string{"S256"}, "revocation_endpoint": issuer + "/revoke"}
		if p.hugeMetadata {
			doc["padding"] = strings.Repeat("x", maxMetadata)
		}
		if p.noS256 {
			doc["code_challenge_methods_supported"] = []string{"plain"}
		}
		if p.noRevocation {
			delete(doc, "revocation_endpoint")
		}
		_ = json.NewEncoder(w).Encode(doc)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		if p.redirectRoot {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		prm(w, r)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", asm)
	mux.HandleFunc("GET /.well-known/openid-configuration", asm)
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		if p.openMCP {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		if !p.noChallenge {
			u := origin + "/.well-known/oauth-protected-resource/mcp"
			if p.challengeURL != "" {
				u = p.challengeURL
			}
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+u+`", scope="mcp"`)
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.misdirect {
			http.Error(w, "misdirected", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func probe(t *testing.T, p proxy) map[string]Result {
	t.Helper()
	var origin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.handler(origin).ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	origin = srv.URL
	return probeAt(t, origin, http.DefaultClient)
}

// probeAt probes origin with client as given: SelfProbe itself must keep redirects unfollowed.
func probeAt(t *testing.T, origin string, client *http.Client) map[string]Result {
	t.Helper()
	res, _ := url.Parse(origin + "/mcp")
	out := map[string]Result{}
	for _, r := range SelfProbe(context.Background(), client, Target{Resource: res, Issuer: origin, HostsSetting: "HOSTS_SETTING"}) {
		if r.Class != ClassProxy {
			t.Errorf("%s: class %q, want proxy", r.Name, r.Class)
		}
		out[r.Name] = r
	}
	return out
}

const (
	prmInserted = "protected resource metadata (path-inserted)"
	prmRoot     = "protected resource metadata (root)"
	asRFC8414   = "authorization server metadata (RFC 8414)"
	asOpenID    = "authorization server metadata (OpenID)"
	challenge   = "unauthenticated MCP request"
	hostHeader  = "Host header"
)

func TestSelfProbeOfAHealthyProxyPasses(t *testing.T) {
	got := probe(t, proxy{})
	for _, name := range []string{prmInserted, prmRoot, asRFC8414, asOpenID, challenge, hostHeader} {
		if got[name].Status != Pass {
			t.Errorf("%s: %+v, want pass", name, got[name])
		}
	}
	if len(got) != 6 {
		t.Errorf("%d checks, want 6", len(got))
	}
}

func TestSelfProbeNamesTheFixForEachMisconfiguration(t *testing.T) {
	cases := []struct {
		name      string
		p         proxy
		check     string
		inMessage string
		inFix     string
	}{
		{"resource is another URL", proxy{resource: "https://other.example/mcp"}, prmInserted, `want "http://127.0.0.1`, "set the public URL"},
		{"another issuer in resource metadata", proxy{issuer: "https://other.example"}, prmRoot, "authorization_servers", "another deployment"},
		{"another issuer in server metadata", proxy{issuer: "https://other.example"}, asOpenID, "issuer is", "not another server"},
		{"no iss parameter flag", proxy{noIssParameter: true}, asRFC8414, "authorization_response_iss_parameter_supported", "not another server"},
		{"no revocation endpoint", proxy{noRevocation: true}, asRFC8414, "revocation_endpoint", "not another server"},
		{"root metadata redirects", proxy{redirectRoot: true}, prmRoot, "redirect to /elsewhere", "pass this path through unchanged"},
		{"Host refused", proxy{misdirect: true}, hostHeader, "421", "HOSTS_SETTING"},
		{"Host refused, on metadata", proxy{misdirect: true}, prmInserted, "answered 421", "HOSTS_SETTING"},
		{"401 without WWW-Authenticate", proxy{noChallenge: true}, challenge, "no resource_metadata", "WWW-Authenticate"},
		{"401 points elsewhere", proxy{challengeURL: "https://other.example/.well-known/oauth-protected-resource"}, challenge, "points at https://other.example", "public URL"},
		{"MCP endpoint open", proxy{openMCP: true}, challenge, "answered 200, want 401", "not the upstream directly"},
		{"metadata too large", proxy{hugeMetadata: true}, prmInserted, "larger than", "pass this path through unchanged"},
		{"server metadata too large", proxy{hugeMetadata: true}, asRFC8414, "larger than", "pass this path through unchanged"},
		{"resource metadata is not JSON", proxy{htmlMetadata: true}, prmRoot, "is not JSON", "pass this path through unchanged"},
		{"server metadata is not JSON", proxy{htmlMetadata: true}, asOpenID, "is not JSON", "pass this path through unchanged"},
		{"no S256", proxy{noS256: true}, asRFC8414, "lacks S256", "not another server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := probe(t, tc.p)[tc.check]
			if r.Status != Fail || !strings.Contains(r.Message, tc.inMessage) || !strings.Contains(r.Fix, tc.inFix) {
				t.Fatalf("%s = %+v\nwant fail, message with %q, fix with %q", tc.check, r, tc.inMessage, tc.inFix)
			}
		})
	}
}

type refusing struct{}

func (refusing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrServerClosed
}

func TestSelfProbeOfAnUnreachableProxyFailsEveryRouteAndSaysStartIt(t *testing.T) {
	got := probeAt(t, "http://127.0.0.1:1", &http.Client{Transport: refusing{}})
	for _, name := range []string{prmInserted, prmRoot, asRFC8414, asOpenID, challenge} {
		if got[name].Status != Fail || !strings.Contains(got[name].Message, "cannot reach") || !strings.Contains(got[name].Fix, "start the proxy") {
			t.Errorf("%s: %+v", name, got[name])
		}
	}
	if got[hostHeader].Status != Skip {
		t.Errorf("Host check of a proxy that never answered: %+v, want skip", got[hostHeader])
	}
}

func TestSelfProbeSendsWhatClientsSend(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Mcp-Protocol-Version")+" auth="+r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	probeAt(t, srv.URL, http.DefaultClient)
	want := []string{
		"GET /.well-known/oauth-protected-resource/mcp " + protocolVersion + " auth=",
		"GET /.well-known/oauth-protected-resource " + protocolVersion + " auth=",
		"GET /.well-known/oauth-authorization-server " + protocolVersion + " auth=",
		"GET /.well-known/openid-configuration " + protocolVersion + " auth=",
		"POST /mcp " + protocolVersion + " auth=",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests\n%s\nwant\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}

func TestSelfProbe404NamesTheRoute(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	if r := probeAt(t, srv.URL, http.DefaultClient)[prmInserted]; r.Status != Fail || !strings.Contains(r.Fix, "route /.well-known/") {
		t.Fatalf("%+v", r)
	}
}
