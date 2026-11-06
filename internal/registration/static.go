package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/corker/mcp-authproxy/internal/idp"
)

// Static-client file limits.
const (
	MaxStaticFileBytes = 1 << 20
	MaxStaticClients   = 1000
	MaxClientIDLen     = 255
	MaxClientNameLen   = 100
	// MinSecretBytes is the shortest accepted client secret.
	MinSecretBytes = 32
)

// staticFile is the --static-clients-file format (ADR-0020 §3). Field names follow RFC 7591.
type staticFile struct {
	Clients []staticEntry `json:"clients"`
}

type staticEntry struct {
	ClientID     string          `json:"client_id"`
	ClientName   string          `json:"client_name"`
	AuthMethod   AuthMethod      `json:"token_endpoint_auth_method"`
	RedirectURIs []string        `json:"redirect_uris"`
	SecretFile   string          `json:"client_secret_file"`
	JWKS         json.RawMessage `json:"jwks"`
	JWKSFile     string          `json:"jwks_file"`
	// Present only to give inline secrets a clear error (ADR-0008 Consequences).
	ClientSecret *string `json:"client_secret"`
}

// StaticRegistry holds the operator's static clients.
type StaticRegistry struct {
	clients map[string]*staticClient
}

// Client returns the static client with id, or ErrUnknownClient.
func (r *StaticRegistry) Client(_ context.Context, id string) (Client, error) {
	c, ok := r.clients[id]
	if !ok {
		return nil, ErrUnknownClient
	}
	return c, nil
}

// LoadStatic reads the static clients file at path. Secret and JWKS file paths inside it are
// relative to its directory. readFile is the only file access (tests pass a map); jti is the replay
// cache for private_key_jwt. Errors name the client and field and never contain secrets.
func LoadStatic(path string, readFile func(string) ([]byte, error), jti JTICache) (Registry, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("static clients: %w", err)
	}
	return parseStatic(data, filepath.Dir(path), readFile, jti)
}

func parseStatic(data []byte, dir string, readFile func(string) ([]byte, error), jti JTICache) (*StaticRegistry, error) {
	if len(data) > MaxStaticFileBytes {
		return nil, fmt.Errorf("static clients: file larger than %d bytes", MaxStaticFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f staticFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("static clients: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("static clients: unexpected data after the JSON object")
	}
	if len(f.Clients) == 0 {
		return nil, errors.New("static clients: no clients")
	}
	if len(f.Clients) > MaxStaticClients {
		return nil, fmt.Errorf("static clients: more than %d clients", MaxStaticClients)
	}
	if jti == nil {
		return nil, errors.New("static clients: a jti cache is required")
	}
	reg := &StaticRegistry{clients: map[string]*staticClient{}}
	for i, e := range f.Clients {
		c, err := buildClient(e, dir, readFile, jti)
		if err != nil {
			name := e.ClientID
			if name == "" || !validClientID(name) {
				name = fmt.Sprintf("clients[%d]", i)
			}
			return nil, fmt.Errorf("static clients: %s: %w", name, err)
		}
		if _, dup := reg.clients[c.id]; dup {
			return nil, fmt.Errorf("static clients: %s: client_id: duplicate", c.id)
		}
		reg.clients[c.id] = c
	}
	return reg, nil
}

func validClientID(id string) bool {
	if id == "" || len(id) > MaxClientIDLen {
		return false
	}
	for _, r := range id {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func buildClient(e staticEntry, dir string, readFile func(string) ([]byte, error), jti JTICache) (*staticClient, error) {
	if !validClientID(e.ClientID) {
		return nil, fmt.Errorf("client_id: required, printable ASCII without spaces, at most %d characters", MaxClientIDLen)
	}
	if e.ClientSecret != nil {
		return nil, errors.New("client_secret: inline secrets are not allowed; use client_secret_file")
	}
	name := e.ClientName
	if name == "" {
		name = e.ClientID
	}
	if len(name) > MaxClientNameLen || strings.ContainsFunc(name, unicode.IsControl) {
		return nil, fmt.Errorf("client_name: at most %d characters, no control characters", MaxClientNameLen)
	}
	if len(e.RedirectURIs) == 0 || len(e.RedirectURIs) > MaxRedirectURIs {
		return nil, fmt.Errorf("redirect_uris: between 1 and %d required", MaxRedirectURIs)
	}
	for i, u := range e.RedirectURIs {
		if err := ValidateRedirect(u); err != nil {
			return nil, fmt.Errorf("redirect_uris[%d]: %w", i, err)
		}
		if slices.Contains(e.RedirectURIs[:i], u) {
			return nil, fmt.Errorf("redirect_uris[%d]: duplicate", i)
		}
	}
	c := &staticClient{id: e.ClientID, name: name, method: e.AuthMethod, redirects: e.RedirectURIs, jti: jti}
	secretMethod := e.AuthMethod == ClientSecretBasic || e.AuthMethod == ClientSecretPost
	switch {
	case e.AuthMethod != None && e.AuthMethod != PrivateKeyJWT && !secretMethod:
		return nil, errors.New("token_endpoint_auth_method: one of none, client_secret_basic, client_secret_post, private_key_jwt")
	case e.SecretFile != "" && !secretMethod:
		return nil, errors.New("client_secret_file: only with client_secret_basic or client_secret_post")
	case (len(e.JWKS) > 0 || e.JWKSFile != "") && e.AuthMethod != PrivateKeyJWT:
		return nil, errors.New("jwks: only with private_key_jwt")
	}
	if secretMethod {
		if e.SecretFile == "" {
			return nil, errors.New("client_secret_file: required for " + string(e.AuthMethod))
		}
		b, err := readFile(resolve(dir, e.SecretFile))
		if err != nil {
			return nil, fmt.Errorf("client_secret_file: %w", err)
		}
		secret := strings.TrimRight(string(b), "\r\n")
		if len(secret) < MinSecretBytes {
			return nil, fmt.Errorf("client_secret_file: the secret must be at least %d bytes", MinSecretBytes)
		}
		c.secret = secret
	}
	if e.AuthMethod == PrivateKeyJWT {
		raw := []byte(e.JWKS)
		switch {
		case len(e.JWKS) > 0 && e.JWKSFile != "":
			return nil, errors.New("jwks, jwks_file: give one, not both")
		case e.JWKSFile != "":
			b, err := readFile(resolve(dir, e.JWKSFile))
			if err != nil {
				return nil, fmt.Errorf("jwks_file: %w", err)
			}
			raw = b
		case len(e.JWKS) == 0:
			return nil, errors.New("jwks: required for private_key_jwt (or jwks_file)")
		}
		set, err := idp.ParseJWKS(raw)
		if err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		for _, k := range set.Keys {
			if !k.IsPublic() {
				return nil, errors.New("jwks: contains a private key; register public keys only")
			}
		}
		if idp.SigningKeys(set) == 0 {
			return nil, errors.New("jwks: no usable public signing key")
		}
		c.keys = idp.StaticKeys(set)
	}
	return c, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// staticClient is a client from the operator's file; its trust level is Verified (ADR-0008 §8).
type staticClient struct {
	id, name  string
	method    AuthMethod
	redirects []string
	secret    string
	keys      idp.StaticKeys
	jti       JTICache
}

func (c *staticClient) ID() string             { return c.id }
func (c *staticClient) Name() string           { return c.name }
func (c *staticClient) Trust() TrustLevel      { return Verified }
func (c *staticClient) AuthMethod() AuthMethod { return c.method }

// RedirectAllowed applies ADR-0009 against the registered redirect URIs.
func (c *staticClient) RedirectAllowed(redirectURI string) error {
	return MatchRedirect(c.redirects, redirectURI)
}

// String never shows the secret.
func (c *staticClient) String() string {
	return fmt.Sprintf("registration.staticClient{id:%s method:%s}", c.id, c.method)
}

// GoString never shows the secret.
func (c *staticClient) GoString() string { return c.String() }
