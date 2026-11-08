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
	// jwksKey, when set, is the key ID the JWKS serves, and the server metadata names jwks_uri.
	jwksKey   string
	noJWKSURI bool   // jwks_uri left out although there is a JWKS
	jwks404   bool   // jwks_uri named, but nothing served there
	jwksURI   string // overrides the advertised jwks_uri
	hugeJWKS  bool
	// noOpenIDJWKS leaves jwks_uri out of the OpenID document only, keeping it in RFC 8414's.
	noOpenIDJWKS bool
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
		openIDWithout := p.noOpenIDJWKS && r.URL.Path == "/.well-known/openid-configuration"
		if p.jwksKey != "" && !p.noJWKSURI && !openIDWithout {
			doc["jwks_uri"] = origin + "/.well-known/jwks.json"
			if p.jwksURI != "" {
				doc["jwks_uri"] = p.jwksURI
			}
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
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if p.jwksKey == "" || p.jwks404 {
			http.NotFound(w, r)
			return
		}
		if p.hugeJWKS {
			_, _ = w.Write([]byte(`{"keys":[],"padding":"` + strings.Repeat("x", maxMetadata) + `"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "EC", "kid": p.jwksKey}}})
	})
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
	return probeSigning(t, p, "")
}

// probeSigning probes a proxy whose identity assertions are signed by key ("": no assertion).
func probeSigning(t *testing.T, p proxy, key string) map[string]Result {
	t.Helper()
	var origin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.handler(origin).ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	origin = srv.URL
	return probeTarget(t, origin, http.DefaultClient, key)
}

// probeAt probes origin with client as given: SelfProbe itself must keep redirects unfollowed.
func probeAt(t *testing.T, origin string, client *http.Client) map[string]Result {
	t.Helper()
	return probeTarget(t, origin, client, "")
}

func probeTarget(t *testing.T, origin string, client *http.Client, key string) map[string]Result {
	t.Helper()
	res, _ := url.Parse(origin + "/mcp")
	out := map[string]Result{}
	for _, r := range SelfProbe(context.Background(), client, Target{Resource: res, Issuer: origin, HostsSetting: "HOSTS_SETTING", AssertionKeyID: key}) {
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
	keysByDisco = "identity assertion keys (discovery)"
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

// With an identity assertion, discovery must lead a verifier that uses nothing else to the signing
// key, as MCP Toolbox's generic auth does: openid-configuration names byward's issuer and a jwks_uri
// serving the key (ADR-0016 amendment, #207). Without one, the check is not run.
func TestSelfProbeFollowsDiscoveryToTheAssertionKey(t *testing.T) {
	if got := probeSigning(t, proxy{jwksKey: "k1"}, "k1")[keysByDisco]; got.Status != Pass || !strings.Contains(got.Message, "serves the signing key k1") {
		t.Fatalf("healthy: %+v", got)
	}
	if _, ran := probe(t, proxy{})[keysByDisco]; ran {
		t.Fatal("the check ran without an identity assertion")
	}
	for name, tc := range map[string]struct {
		p         proxy
		inMessage string
		inFix     string
	}{
		"no jwks_uri":                          {proxy{jwksKey: "k1", noJWKSURI: true}, "does not name the issuer", "pass this path through unchanged"},
		"another issuer":                       {proxy{jwksKey: "k1", issuer: "https://other.example"}, "does not name the issuer", "pass this path through unchanged"},
		"the JWKS is missing":                  {proxy{jwksKey: "k1", jwks404: true}, "answered 404", "route /.well-known/"},
		"another key":                          {proxy{jwksKey: "k0"}, "does not serve the signing key k1", "route /.well-known/jwks.json on this host to the proxy"},
		"not JSON":                             {proxy{jwksKey: "k1", htmlMetadata: true}, "does not name the issuer", "pass this path through unchanged"},
		"discovery refused":                    {proxy{jwksKey: "k1", misdirect: true}, "answered 421", "HOSTS_SETTING"},
		"discovery too large":                  {proxy{jwksKey: "k1", hugeMetadata: true}, "larger than", "pass this path through unchanged"},
		"the JWKS too large":                   {proxy{jwksKey: "k1", hugeJWKS: true}, "larger than", "pass this path through unchanged"},
		"jwks_uri only in RFC 8414's document": {proxy{jwksKey: "k1", noOpenIDJWKS: true}, "does not name the issuer", "pass this path through unchanged"},
		"jwks_uri unreachable":                 {proxy{jwksKey: "k1", jwksURI: "http://127.0.0.1:1/.well-known/jwks.json"}, "cannot reach http://127.0.0.1:1/.well-known/jwks.json", "start the proxy"},
	} {
		t.Run(name, func(t *testing.T) {
			got := probeSigning(t, tc.p, "k1")[keysByDisco]
			if got.Status != Fail || !strings.Contains(got.Message, tc.inMessage) || !strings.Contains(got.Fix, tc.inFix) {
				t.Fatalf("%+v\nwant fail, message with %q, fix with %q", got, tc.inMessage, tc.inFix)
			}
		})
	}
}

// A proxy that does not answer fails the discovery check too, saying to start it.
func TestSelfProbeOfAnUnreachableProxyFailsTheDiscoveryCheck(t *testing.T) {
	got := probeTarget(t, "http://127.0.0.1:1", http.DefaultClient, "k1")[keysByDisco]
	if got.Status != Fail || !strings.Contains(got.Message, "cannot reach") || !strings.Contains(got.Fix, "start the proxy") {
		t.Fatalf("%+v", got)
	}
}
