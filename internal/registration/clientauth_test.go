package registration

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
)

const tokenEndpoint = "https://proxy.example/token"

var now = time.Unix(1_800_000_000, 0)

type authEnv struct {
	reg  Registry
	cert *fakeidp.Certificate
	jti  *MemoryJTICache
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	cert := fakeidp.NewCertificate(t)
	jti := NewMemoryJTICache(func() time.Time { return now }, 100)
	reg, err := LoadStatic("/c.json", files{
		"/c.json": `{"clients":[
			{"client_id":"cli","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/cb"]},
			{"client_id":"basic","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://a.example/cb"],"client_secret_file":"s"},
			{"client_id":"post","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"s"},
			{"client_id":"jwt","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":` + publicJWKS(t, cert) + `}
		]}`,
		"/s": goodSecret,
	}.read, jti)
	if err != nil {
		t.Fatal(err)
	}
	return &authEnv{reg: reg, cert: cert, jti: jti}
}

func (e *authEnv) auth(t *testing.T, id string, form url.Values, h http.Header) error {
	t.Helper()
	c, err := e.reg.Client(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = http.Header{}
	}
	return c.Authenticate(context.Background(), form, h, tokenEndpoint, now)
}

func basicHeader(id, secret string) http.Header {
	r, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	return r.Header
}

func (e *authEnv) assertion(t *testing.T, signer *fakeidp.Certificate, alg string, override map[string]any) url.Values {
	t.Helper()
	claims := map[string]any{"iss": "jwt", "sub": "jwt", "aud": tokenEndpoint, "jti": fakeidp.NewGUID(),
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix()}
	for k, v := range override {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	s, err := signer.SignJWT(alg, map[string]any{"kid": "k0"}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"client_id": {"jwt"}, "client_assertion_type": {clientAssertionType}, "client_assertion": {s}}
}

func TestAuthenticate(t *testing.T) {
	e := newAuthEnv(t)
	stranger := fakeidp.NewCertificate(t)
	for name, tc := range map[string]struct {
		id     string
		form   func() url.Values
		header http.Header
		reason string // "" = accepted
	}{
		"none":                    {id: "cli", form: func() url.Values { return url.Values{"client_id": {"cli"}} }},
		"none with secret":        {id: "cli", form: func() url.Values { return url.Values{"client_id": {"cli"}, "client_secret": {"x"}} }, reason: "registered none, sent client_secret_post"},
		"basic":                   {id: "basic", form: url.Values{}.Clone, header: basicHeader("basic", goodSecret)},
		"basic wrong secret":      {id: "basic", form: url.Values{}.Clone, header: basicHeader("basic", goodSecret+"x"), reason: "secret does not match"},
		"basic other id":          {id: "basic", form: url.Values{}.Clone, header: basicHeader("post", goodSecret), reason: "Basic client ID"},
		"basic sent as post":      {id: "basic", form: func() url.Values { return url.Values{"client_id": {"basic"}, "client_secret": {goodSecret}} }, reason: "registered client_secret_basic, sent client_secret_post"},
		"basic and post":          {id: "basic", form: func() url.Values { return url.Values{"client_secret": {goodSecret}} }, header: basicHeader("basic", goodSecret), reason: "more than one"},
		"post":                    {id: "post", form: func() url.Values { return url.Values{"client_id": {"post"}, "client_secret": {goodSecret}} }},
		"post empty":              {id: "post", form: func() url.Values { return url.Values{"client_id": {"post"}, "client_secret": {""}} }, reason: "secret does not match"},
		"post no credential":      {id: "post", form: func() url.Values { return url.Values{"client_id": {"post"}} }, reason: "registered client_secret_post, sent none"},
		"form client_id mismatch": {id: "post", form: func() url.Values { return url.Values{"client_id": {"basic"}, "client_secret": {goodSecret}} }, reason: "client_id does not match"},
		"jwt PS256":               {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "PS256", nil) }},
		"jwt RS256":               {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "RS256", nil) }},
		"jwt aud array": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"aud": []any{"x", tokenEndpoint}})
		}},
		"jwt other key": {id: "jwt", form: func() url.Values { return e.assertion(t, stranger, "PS256", nil) }, reason: "signature"},
		"jwt wrong aud": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"aud": "https://other.example/token"})
		}, reason: "aud"},
		"jwt wrong iss": {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "PS256", map[string]any{"iss": "post"}) }, reason: "iss and sub"},
		"jwt wrong sub": {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "PS256", map[string]any{"sub": "post"}) }, reason: "iss and sub"},
		"jwt no exp":    {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "PS256", map[string]any{"exp": nil}) }, reason: "no exp"},
		"jwt expired": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"exp": now.Add(-AssertionLeeway).Unix()})
		}, reason: "expired"},
		"jwt expired within leeway": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"exp": now.Add(-AssertionLeeway + time.Second).Unix()})
		}},
		"jwt exp too far": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"exp": now.Add(6 * time.Minute).Unix()})
		}, reason: "more than 5 minutes"},
		"jwt exp at 5 min": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"exp": now.Add(5 * time.Minute).Unix()})
		}},
		"jwt iat in the future": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"iat": now.Add(time.Minute).Unix()})
		}, reason: "iat is in the future"},
		"jwt nbf in the future": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"nbf": now.Add(time.Minute).Unix()})
		}, reason: "nbf is in the future"},
		"jwt no iat": {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "PS256", map[string]any{"iat": nil}) }},
		"jwt no jti": {id: "jwt", form: func() url.Values { return e.assertion(t, e.cert, "PS256", map[string]any{"jti": nil}) }, reason: "jti"},
		"jwt long jti": {id: "jwt", form: func() url.Values {
			return e.assertion(t, e.cert, "PS256", map[string]any{"jti": strings.Repeat("j", MaxJTILen+1)})
		}, reason: "jti"},
		"jwt wrong type": {id: "jwt", form: func() url.Values {
			f := e.assertion(t, e.cert, "PS256", nil)
			f.Set("client_assertion_type", "urn:example")
			return f
		}, reason: "client_assertion_type"},
		"jwt as secret": {id: "jwt", form: func() url.Values { return url.Values{"client_id": {"jwt"}, "client_secret": {goodSecret}} }, reason: "registered private_key_jwt, sent client_secret_post"},
	} {
		t.Run(name, func(t *testing.T) {
			err := e.auth(t, tc.id, tc.form(), tc.header)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidClient) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want invalid_client with %q", err, tc.reason)
			}
			if strings.Contains(err.Error(), goodSecret) {
				t.Fatal("error contains the secret")
			}
		})
	}
}

func TestAssertionReplayIsRejected(t *testing.T) {
	e := newAuthEnv(t)
	form := e.assertion(t, e.cert, "PS256", nil)
	if err := e.auth(t, "jwt", form, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.auth(t, "jwt", form, nil); !errors.Is(err, ErrInvalidClient) || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay: %v", err)
	}
}

func TestJTICacheFailureIsNotInvalidClient(t *testing.T) {
	e := newAuthEnv(t)
	e.jti.maxEntries = 0
	err := e.auth(t, "jwt", e.assertion(t, e.cert, "PS256", nil), nil)
	if err == nil || errors.Is(err, ErrInvalidClient) || !errors.Is(err, ErrJTICacheFull) {
		t.Fatalf("err = %v", err)
	}
}

func TestRedirectAllowedUsesRegisteredURIs(t *testing.T) {
	e := newAuthEnv(t)
	c, _ := e.reg.Client(context.Background(), "cli")
	if err := c.RedirectAllowed("http://127.0.0.1:4321/cb"); err != nil {
		t.Fatal(err)
	}
	if err := c.RedirectAllowed("https://a.example/cb"); err == nil {
		t.Fatal("other client's redirect accepted")
	}
}
