package registration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const goodSecret = "0123456789abcdef0123456789abcdef+%/:secret"

// files is a readFile over an in-memory map.
type files map[string]string

func (f files) read(p string) ([]byte, error) {
	s, ok := f[p]
	if !ok {
		return nil, fmt.Errorf("open %s: %w", p, fs.ErrNotExist)
	}
	return []byte(s), nil
}

func publicJWKS(t testing.TB, keys ...*fakeidp.Certificate) string {
	t.Helper()
	var set jose.JSONWebKeySet
	for i, c := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &c.Key.PublicKey, KeyID: fmt.Sprintf("k%d", i), Use: "sig", Algorithm: "PS256"})
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func load(t *testing.T, fs files) (Registry, error) {
	t.Helper()
	return LoadStatic("/etc/mcp/clients.json", fs.read, NewMemoryJTICache(time.Now, 100))
}

func TestLoadStaticAllMethods(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	fs := files{
		"/etc/mcp/clients.json": `{"clients":[
			{"client_id":"cli","client_name":"CLI","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]},
			{"client_id":"basic","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://app.example/cb"],"client_secret_file":"secrets/basic"},
			{"client_id":"post","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://app.example/cb"],"client_secret_file":"/run/secrets/post"},
			{"client_id":"jwt","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://app.example/cb"],"jwks":` + publicJWKS(t, cert) + `},
			{"client_id":"jwtfile","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://app.example/cb"],"jwks_file":"jwks.json"}
		]}`,
		"/etc/mcp/secrets/basic": goodSecret + "\n",
		"/run/secrets/post":      goodSecret,
		"/etc/mcp/jwks.json":     publicJWKS(t, cert),
	}
	reg, err := load(t, fs)
	if err != nil {
		t.Fatal(err)
	}
	for id, method := range map[string]AuthMethod{"cli": None, "basic": ClientSecretBasic, "post": ClientSecretPost, "jwt": PrivateKeyJWT, "jwtfile": PrivateKeyJWT} {
		c, err := reg.Client(context.Background(), id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if c.AuthMethod() != method || c.Trust() != Verified || c.ID() != id {
			t.Errorf("%s: method %s trust %s", id, c.AuthMethod(), c.Trust())
		}
	}
	if c, _ := reg.Client(context.Background(), "cli"); c.Name() != "CLI" {
		t.Errorf("name = %q", c.Name())
	}
	if c, _ := reg.Client(context.Background(), "post"); c.Name() != "post" {
		t.Errorf("default name = %q", c.Name())
	}
	if _, err := reg.Client(context.Background(), "nope"); !errors.Is(err, ErrUnknownClient) {
		t.Errorf("unknown client: %v", err)
	}
	if c, _ := reg.Client(context.Background(), "basic"); strings.Contains(fmt.Sprintf("%v %+v %#v %s %d %x %q", c, c, c, c, c, c, c), goodSecret) {
		t.Error("client formats its secret")
	}
}

func TestLoadStaticRejects(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	private, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: cert.Key, KeyID: "k", Use: "sig"}}})
	entry := func(fields string) string { return `{"clients":[{` + fields + `}]}` }
	ok := `"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]`
	for name, tc := range map[string]struct {
		file    string
		extra   files
		wantErr string
	}{
		"not JSON":             {file: `{`, wantErr: "unexpected end of input"},
		"wrong type":           {file: `{"clients":[{"client_id":7}]}`, wantErr: "wrong JSON type at byte"},
		"trailing data":        {file: entry(ok) + `{}`, wantErr: "unexpected data"},
		"unknown field":        {file: entry(ok + `,"scope":"x"`), wantErr: "unknown field"},
		"unknown top field":    {file: `{"clients":[{` + ok + `}],"extra":1}`, wantErr: "unknown field"},
		"no clients":           {file: `{"clients":[]}`, wantErr: "no clients"},
		"missing client_id":    {file: entry(`"token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]`), wantErr: "clients[0]: client_id"},
		"client_id with space": {file: entry(`"client_id":"a b","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]`), wantErr: "clients[0]: client_id"},
		"duplicate client":     {file: `{"clients":[{` + ok + `},{` + ok + `}]}`, wantErr: "c: client_id: duplicate"},
		"inline secret": {file: entry(`"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret":"` + goodSecret + `"`),
			wantErr: "c: client_secret: inline secrets are not allowed"},
		"unknown method":      {file: entry(`"client_id":"c","token_endpoint_auth_method":"tls_client_auth","redirect_uris":["https://a.example/cb"]`), wantErr: "c: token_endpoint_auth_method"},
		"missing method":      {file: entry(`"client_id":"c","redirect_uris":["https://a.example/cb"]`), wantErr: "c: token_endpoint_auth_method"},
		"no redirect":         {file: entry(`"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":[]`), wantErr: "c: redirect_uris: between 1 and"},
		"bad redirect":        {file: entry(`"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["http://a.example/cb"]`), wantErr: "c: redirect_uris[0]"},
		"duplicate redirect":  {file: entry(`"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb","https://a.example/cb"]`), wantErr: "c: redirect_uris[1]: duplicate"},
		"too many redirects":  {file: entry(`"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":[` + manyRedirects(MaxRedirectURIs+1) + `]`), wantErr: "c: redirect_uris: between 1 and"},
		"secret file missing": {file: entry(`"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"]`), wantErr: "c: client_secret_file: required"},
		"secret file absent":  {file: entry(`"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"nope"`), wantErr: "c: client_secret_file: open"},
		"short secret": {file: entry(`"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"s"`),
			extra: files{"/etc/mcp/s": "short"}, wantErr: "at least 32 bytes"},
		"secret for none": {file: entry(ok + `,"client_secret_file":"s"`), extra: files{"/etc/mcp/s": goodSecret}, wantErr: "c: client_secret_file: only with"},
		"jwks for secret": {file: entry(`"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"s","jwks":{"keys":[]}`),
			extra: files{"/etc/mcp/s": goodSecret}, wantErr: "c: jwks: only with private_key_jwt"},
		"jwt without jwks":  {file: entry(`"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"]`), wantErr: "c: jwks: required"},
		"jwt both jwks":     {file: entry(`"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":{"keys":[]},"jwks_file":"j"`), wantErr: "give one"},
		"jwt empty jwks":    {file: entry(`"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":{"keys":[]}`), wantErr: "no usable public signing key"},
		"jwt private key":   {file: entry(`"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":` + string(private)), wantErr: "contains a private key"},
		"jwt enc key only":  {file: entry(`"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":` + strings.Replace(publicJWKS(t, cert), `"sig"`, `"enc"`, 1)), wantErr: "no usable public signing key"},
		"weak RSA key":      {file: entry(`"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],"jwks":` + weakJWKS(t)), wantErr: "at least 2048 bits"},
		"control char name": {file: entry(ok + `,"client_name":"a\u0007b"`), wantErr: "c: client_name"},
		"too big":           {file: strings.Repeat(" ", MaxStaticFileBytes+1), wantErr: "larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			fs := files{"/etc/mcp/clients.json": tc.file}
			for k, v := range tc.extra {
				fs[k] = v
			}
			_, err := load(t, fs)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), goodSecret) {
				t.Fatal("error contains the secret")
			}
		})
	}
}

func manyRedirects(n int) string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(`"https://a.example/cb%d"`, i)
	}
	return strings.Join(out, ",")
}

func TestLoadStaticNeedsJTICacheAndReadableFile(t *testing.T) {
	if _, err := LoadStatic("/x", files{"/x": `{"clients":[{"client_id":"c","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]}]}`}.read, nil); err == nil {
		t.Error("nil jti cache accepted")
	}
	if _, err := LoadStatic("/missing", files{}.read, NewMemoryJTICache(time.Now, 1)); err == nil {
		t.Error("missing file accepted")
	}
}

func weakJWKS(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak for the test
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "w", Use: "sig"}}})
	return string(b)
}

// A secret-looking file in any JSON setting must never be echoed into the error (invariant 2).
func TestJSONErrorsNeverQuoteTheInput(t *testing.T) {
	const secretish = "dGhpcy1pcy1hLXNlY3JldC12YWx1ZQ"
	jwtClient := func(field string) string {
		return `{"clients":[{"client_id":"c","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"],` + field + `}]}`
	}
	for name, fs := range map[string]files{
		"static file is a secret":  {"/etc/mcp/clients.json": secretish + "\n"},
		"static file starts JSON":  {"/etc/mcp/clients.json": `{"clients":[` + secretish},
		"unknown field from input": {"/etc/mcp/clients.json": `{"` + secretish + `":1}`},
		"jwks_file is a secret":    {"/etc/mcp/clients.json": jwtClient(`"jwks_file":"j"`), "/etc/mcp/j": secretish},
		"jwks_file half JSON":      {"/etc/mcp/clients.json": jwtClient(`"jwks_file":"j"`), "/etc/mcp/j": `{"keys":` + secretish},
		"inline jwks wrong type":   {"/etc/mcp/clients.json": jwtClient(`"jwks":{"keys":"` + secretish + `"}`)},
		"secret file is JSON-ish":  {"/etc/mcp/clients.json": `{"clients":[{"client_id":"c","token_endpoint_auth_method":"client_secret_post","redirect_uris":["https://a.example/cb"],"client_secret_file":"s"}]}`, "/etc/mcp/s": "{" + secretish[:8]},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, fs)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, leak := range []string{secretish[:4], "'d'", "invalid character"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error %q leaks %q", err, leak)
				}
			}
		})
	}
}
