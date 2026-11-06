package registration

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const cimdID = "https://app.example/oauth/client.json"

func TestOnlyClientIDURLsMeetingDraftSection3AreAccepted(t *testing.T) {
	for _, ok := range []string{
		"https://claude.ai/oauth/claude-code-client-metadata",
		"https://vscode.dev/oauth/client-metadata.json",
		"https://app.example:443/client", // a different client ID from the one without :443 (§3)
		"https://app.example/a/b/",
		"https://app.example/" + strings.Repeat("a", MaxCIMDURLLen-len("https://app.example/")), // exactly the limit
	} {
		if err := ValidateCIMDURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for name, id := range map[string]string{
		"http":            "http://app.example/client",
		"no path":         "https://app.example",
		"root path":       "https://app.example/",
		"query":           "https://app.example/client?v=1",
		"fragment":        "https://app.example/client#x",
		"userinfo":        "https://user@app.example/client",
		"dot segment":     "https://app.example/a/./client",
		"dot-dot segment": "https://app.example/a/../client",
		"escaped dot-dot": "https://app.example/a/%2e%2e/client",
		"other port":      "https://app.example:8443/client",
		"unicode host":    "https://bücher.example/client",
		"space":           "https://app.example/a client",
		"too long":        "https://app.example/" + strings.Repeat("a", MaxCIMDURLLen-len("https://app.example/")+1),
		"upper scheme":    "HTTPS://app.example/client",
		"no host":         "https:///client",
		"bad escape":      "https://app.example/%zz/client", // fails only in url.Parse
	} {
		if err := ValidateCIMDURL(id); err == nil {
			t.Errorf("%s: %q accepted", name, id)
		}
	}
}

// methodsOf is each published document's token endpoint auth methods as parsed: public clients,
// except ChatGPT's, which offers a signed assertion first (its preferred method) and none.
var methodsOf = map[string][]AuthMethod{"chatgpt": {PrivateKeyJWT, None}}

// The documents real clients publish are accepted, with grants cut to what the broker supports.
func TestRealClientDocumentsAreAccepted(t *testing.T) {
	for _, name := range clientdocs.Names {
		t.Run(name, func(t *testing.T) {
			d := clientdocs.Load(t, name)
			m, err := parseCIMD(d.ClientID, d.Body)
			if err != nil {
				t.Fatal(err)
			}
			want, ok := methodsOf[name]
			if !ok {
				want = []AuthMethod{None}
			}
			if !slices.Equal(m.methods, want) || !slices.Equal(m.grants, []string{"authorization_code", "refresh_token"}) {
				t.Fatalf("methods %v (want %v), grants %v", m.methods, want, m.grants)
			}
			if err := MatchRedirect(m.redirects, d.Redirect); err != nil {
				t.Fatalf("redirect %s: %v", d.Redirect, err)
			}
		})
	}
}

func doc(fields map[string]any) []byte {
	d := map[string]any{"client_id": cimdID, "client_name": "App", "redirect_uris": []string{"https://app.example/cb"}}
	for k, v := range fields {
		if v == nil {
			delete(d, k)
		} else {
			d[k] = v
		}
	}
	b, _ := json.Marshal(d)
	return b
}

func TestADocumentWithoutAMethodIsPublicWithOnlyTheCodeGrant(t *testing.T) {
	m, err := parseCIMD(cimdID, doc(nil))
	if err != nil {
		t.Fatal(err)
	}
	// §5: no method means none, never RFC 7591's client_secret_basic default.
	if !slices.Equal(m.methods, []AuthMethod{None}) || !slices.Equal(m.grants, []string{"authorization_code"}) || m.name != "App" {
		t.Fatalf("%+v", m)
	}
}

func TestUnsupportedListedAuthMethodsAreDroppedAndTheRestKept(t *testing.T) {
	// The single field comes first, then the list, each method once.
	m, err := parseCIMD(cimdID, doc(map[string]any{"token_endpoint_auth_method": "none", "token_endpoint_auth_methods_supported": []string{"tls_client_auth", "private_key_jwt", "none"},
		"jwks_uri": "https://app.example/jwks.json"}))
	if err != nil || !slices.Equal(m.methods, []AuthMethod{None, PrivateKeyJWT}) || m.jwksURI == "" {
		t.Fatalf("%+v, %v", m, err)
	}
}

func TestInvalidDocumentsAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		body []byte
		want string
	}{
		"client_id differs":                {doc(map[string]any{"client_id": "https://evil.example/client.json"}), "does not match"},
		"client_id with :443":              {doc(map[string]any{"client_id": "https://app.example:443/oauth/client.json"}), "does not match"},
		"no name":                          {doc(map[string]any{"client_name": nil}), "client_name"},
		"blank name":                       {doc(map[string]any{"client_name": "  "}), "client_name"},
		"name too long":                    {doc(map[string]any{"client_name": strings.Repeat("a", MaxClientNameLen+1)}), "client_name"},
		"control in name":                  {doc(map[string]any{"client_name": "App\u0007"}), "client_name"},
		"no redirects":                     {doc(map[string]any{"redirect_uris": nil}), "redirect_uris: between 1 and"},
		"custom scheme redirect":           {doc(map[string]any{"redirect_uris": []string{"myapp://cb"}}), "redirect_uris[0]: redirect URI myapp://cb rejected"},
		"client secret":                    {doc(map[string]any{"client_secret": "s3cret"}), "client_secret"},
		"secret expiry":                    {doc(map[string]any{"client_secret_expires_at": 0}), "client_secret"},
		"symmetric method":                 {doc(map[string]any{"token_endpoint_auth_method": "client_secret_basic"}), "shared secret"},
		"symmetric among supported":        {doc(map[string]any{"token_endpoint_auth_methods_supported": []string{"none", "client_secret_jwt"}}), "shared secret"},
		"only unsupported methods":         {doc(map[string]any{"token_endpoint_auth_method": "tls_client_auth"}), "none of the listed"},
		"refresh grant without code grant": {doc(map[string]any{"grant_types": []string{"refresh_token"}}), "grant_types: must include authorization_code"},
		"no authorization_code":            {doc(map[string]any{"grant_types": []string{"client_credentials"}}), "authorization_code"},
		"no code response":                 {doc(map[string]any{"response_types": []string{"token"}}), "response_types"},
		"jwks and jwks_uri":                {doc(map[string]any{"jwks": map[string]any{"keys": []any{}}, "jwks_uri": "https://app.example/jwks"}), "one, not both"},
		"private_key_jwt no keys":          {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt"}), "jwks: required"},
		"jwks_uri with user info":          {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://u:p@app.example/jwks"}), "jwks_uri: must be an https URL"},
		"jwks_uri without a host":          {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https:///jwks"}), "jwks_uri: must be an https URL"},
		"unparsable jwks_uri":              {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://app.example/%zz"}), "jwks_uri: must be an https URL"},
		"jwks_uri with a fragment":         {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://app.example/jwks#k"}), "jwks_uri: must be an https URL"},
		"http jwks_uri":                    {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "http://app.example/jwks"}), "jwks_uri: must be an https URL"},
		"inline private key":               {doc(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": privateJWKS(t)}), "private key"},
		"trailing data":                    {append(doc(nil), []byte(` {}`)...), "trailing"},
		"not an object":                    {[]byte(`["x"]`), "not a JSON object"},
		"name of the wrong type":           {[]byte(`{"client_id":"` + cimdID + `","client_name":7}`), "client_name: wrong JSON type (number)"},
		"redirect_uris of the wrong type":  {[]byte(`{"client_id":"` + cimdID + `","client_name":"A","redirect_uris":"https://app.example/cb"}`), "redirect_uris: wrong JSON type (string)"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCIMD(cimdID, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func FuzzParseCIMD(f *testing.F) {
	for _, n := range clientdocs.Names {
		f.Add(clientdocs.Load(f, n).Body)
	}
	f.Add(doc(map[string]any{"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "none"}, "jwks_uri": "https://app.example/jwks"}))
	f.Fuzz(func(t *testing.T, body []byte) {
		var probe struct {
			ClientID string `json:"client_id"`
		}
		_ = json.Unmarshal(body, &probe)
		id := probe.ClientID
		if id == "" {
			id = cimdID
		}
		m, err := parseCIMD(id, body)
		if err != nil {
			return
		}
		if m.name == "" || len(m.redirects) == 0 || len(m.redirects) > MaxRedirectURIs || !slices.Contains(m.grants, "authorization_code") {
			t.Fatalf("accepted %+v", m)
		}
		for _, r := range m.redirects {
			if ValidateRedirect(r) != nil {
				t.Fatalf("invalid redirect accepted: %q", r)
			}
		}
		for _, meth := range m.methods {
			if meth != None && meth != PrivateKeyJWT {
				t.Fatalf("method %q accepted", meth)
			}
		}
		if slices.Contains(m.methods, PrivateKeyJWT) && len(m.jwks.Keys) == 0 && m.jwksURI == "" {
			t.Fatal("private_key_jwt without keys accepted")
		}
	})
}

func privateJWKS(t *testing.T) json.RawMessage {
	t.Helper()
	cert := fakeidp.NewCertificate(t)
	b, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: cert.Key, KeyID: "k", Use: "sig"}}})
	return b
}

func TestANameAtTheLengthLimitIsAccepted(t *testing.T) {
	if _, err := parseCIMD(cimdID, doc(map[string]any{"client_name": strings.Repeat("a", MaxClientNameLen)})); err != nil {
		t.Fatal(err)
	}
}
