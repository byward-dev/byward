package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAuth authenticates the IdP app at the token endpoint (ADR-0011 §4). It is shared by all
// adapters and never formats its secret.
type ClientAuth interface {
	// Apply adds the credential to a token request for clientID; audience is the token endpoint.
	Apply(form url.Values, clientID, audience string, now time.Time) error
}

type clientSecret struct{ secret string }

// ClientSecret sends client_secret in the request body (client_secret_post).
func ClientSecret(secret string) ClientAuth { return clientSecret{secret} }

func (c clientSecret) Apply(form url.Values, clientID, _ string, _ time.Time) error {
	if c.secret == "" {
		return errors.New("idp: empty client secret")
	}
	form.Set("client_id", clientID)
	form.Set("client_secret", c.secret)
	return nil
}

func (c clientSecret) String() string   { return "idp.ClientSecret(<redacted>)" }
func (c clientSecret) GoString() string { return c.String() }

type privateKeyJWT struct {
	signer jose.Signer
}

// PrivateKeyJWT signs a client assertion with key. RSA keys use PS256, EC P-256 keys ES256. With
// cert, the header carries x5t#S256 (what Entra matches on, ADR-0012 §5); keyID, if set, becomes
// `kid` (what most other IdPs match on).
func PrivateKeyJWT(key crypto.Signer, cert *x509.Certificate, keyID string) (ClientAuth, error) {
	var alg jose.SignatureAlgorithm
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		alg = jose.PS256
	case *ecdsa.PublicKey:
		if k.Curve.Params().Name != "P-256" {
			return nil, errors.New("idp: EC client keys must use P-256")
		}
		alg = jose.ES256
	default:
		return nil, fmt.Errorf("idp: unsupported client key type %T", k)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if cert != nil {
		sum := sha256.Sum256(cert.Raw)
		opts = opts.WithHeader("x5t#S256", base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	if keyID != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), keyID)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return nil, err
	}
	return privateKeyJWT{signer: s}, nil
}

func (p privateKeyJWT) Apply(form url.Values, clientID, audience string, now time.Time) error {
	jti := rand.Text()
	assertion, err := jwt.Signed(p.signer).Claims(jwt.Claims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.Audience{audience},
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).Serialize()
	if err != nil {
		return err
	}
	setAssertion(form, clientID, assertion)
	return nil
}

func (privateKeyJWT) String() string { return "idp.PrivateKeyJWT(<redacted>)" }

type assertionFile struct{ path string }

// AssertionFile sends the JWT in path as the client assertion, re-reading it on every call
// (workload identity, e.g. AZURE_FEDERATED_TOKEN_FILE).
func AssertionFile(path string) ClientAuth { return assertionFile{path} }

func (a assertionFile) Apply(form url.Values, clientID, _ string, _ time.Time) error {
	b, err := os.ReadFile(a.path)
	if err != nil {
		return fmt.Errorf("idp: read client assertion file: %w", err)
	}
	assertion := strings.TrimSpace(string(b))
	if assertion == "" {
		return errors.New("idp: client assertion file is empty")
	}
	setAssertion(form, clientID, assertion)
	return nil
}

func setAssertion(form url.Values, clientID, assertion string) {
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", assertion)
}
