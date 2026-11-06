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
	"sort"
	"strings"
	"unicode"

	"github.com/byward-dev/byward/internal/idp"
)

// Static-client file limits.
const (
	MaxStaticFileBytes = 1 << 20
	MaxStaticClients   = 1000
	MaxClientIDLen     = 255
	MaxClientNameLen   = 100
	// MinSecretBytes is the shortest accepted client secret.
	MinSecretBytes = 32
	// MinRSABits is the smallest accepted RSA client key.
	MinRSABits = 2048
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

// IDs lists the static clients' IDs, sorted (for the client_registered audit events at startup).
func (r *StaticRegistry) IDs() []string {
	ids := make([]string, 0, len(r.clients))
	for id := range r.clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// LoadOption configures LoadStatic.
type LoadOption func(*loadOptions)

type loadOptions struct{ checkSecret func(path string) error }

// WithSecretCheck runs check on each client_secret_file before it is read; the server passes the
// permission check for secret files (ADR-0018 §11). JWKS files hold public keys and are not checked.
func WithSecretCheck(check func(path string) error) LoadOption {
	return func(o *loadOptions) { o.checkSecret = check }
}

// LoadStatic reads the static clients file at path. Secret and JWKS file paths inside it are
// relative to its directory. readFile is the only file access (tests pass a map); jti is the replay
// cache for private_key_jwt. Errors name the client and field and never contain secrets.
func LoadStatic(path string, readFile func(string) ([]byte, error), jti JTICache, opts ...LoadOption) (*StaticRegistry, error) {
	o := loadOptions{checkSecret: func(string) error { return nil }}
	for _, f := range opts {
		f(&o)
	}
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("static clients: %w", err)
	}
	readSecret := func(p string) ([]byte, error) {
		if err := o.checkSecret(p); err != nil {
			return nil, err
		}
		return readFile(p)
	}
	return parseStatic(data, filepath.Dir(path), readFile, readSecret, jti)
}

func parseStatic(data []byte, dir string, readFile, readSecret func(string) ([]byte, error), jti JTICache) (*StaticRegistry, error) {
	if len(data) > MaxStaticFileBytes {
		return nil, fmt.Errorf("static clients: file larger than %d bytes", MaxStaticFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f staticFile
	if err := dec.Decode(&f); err != nil {
		// encoding/json's unknown-field error is untyped and quotes the name from the input; its
		// offset is the end of the object, so neither is reported.
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return nil, errors.New("static clients: unknown field (field names must match the documented format)")
		}
		return nil, fmt.Errorf("static clients: %w", idp.JSONError(err))
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
		c, err := buildClient(e, dir, readFile, readSecret, jti)
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

func buildClient(e staticEntry, dir string, readFile, readSecret func(string) ([]byte, error), jti JTICache) (*staticClient, error) {
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
	if err := ValidateRedirects(e.RedirectURIs); err != nil {
		return nil, err
	}
	c := &staticClient{name: name, redirects: e.RedirectURIs,
		clientAuth: clientAuth{id: e.ClientID, methods: []AuthMethod{e.AuthMethod}, jti: jti}}
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
		b, err := readSecret(resolve(dir, e.SecretFile))
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
		keys, err := parseClientJWKS(raw)
		if err != nil {
			return nil, err
		}
		c.keys = keys
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
	clientAuth
	name      string
	redirects []string
}

func (c *staticClient) ID() string                { return c.id }
func (c *staticClient) Name() string              { return c.name }
func (c *staticClient) Trust() TrustLevel         { return Verified }
func (c *staticClient) AuthMethods() []AuthMethod { return slices.Clone(c.methods) }

// AllowsRefresh is true: static clients are configured by the operator, who controls offline_access.
func (c *staticClient) AllowsRefresh() bool { return true }

// RedirectAllowed applies ADR-0009 against the registered redirect URIs.
func (c *staticClient) RedirectAllowed(redirectURI string) error {
	return MatchRedirect(c.redirects, redirectURI)
}

// String never shows the secret.
func (c *staticClient) String() string {
	return fmt.Sprintf("registration.staticClient{id:%s methods:%v}", c.id, c.methods)
}

// GoString never shows the secret.
func (c *staticClient) GoString() string { return c.String() }

// Format makes every fmt verb use String, so no verb can reach the secret by reflection.
func (c *staticClient) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }
