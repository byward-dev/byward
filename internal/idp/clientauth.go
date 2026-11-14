package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
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
	alg    jose.SignatureAlgorithm
	keyID  string
}

// ErrClientKeyAlg means the client key cannot sign with the chosen algorithm.
var ErrClientKeyAlg = errors.New("idp: the client key cannot sign with that algorithm")

var _ AssertionInfo = privateKeyJWT{} // PrivateKeyJWT's credentials describe themselves

// AssertionInfo describes a private_key_jwt credential: its algorithm and key ID, for the
// operator's diagnosis. Neither is secret. PrivateKeyJWT's credentials implement it.
type AssertionInfo interface {
	SigningAlgorithm() string
	KeyID() string
}

// PrivateKeyJWT signs a client assertion with key. RSA keys use PS256, EC P-256 keys ES256. With
// cert, the header carries x5t#S256 (what Entra matches on, ADR-0012 §5); keyID, if set, becomes
// `kid` (what most other IdPs match on).
func PrivateKeyJWT(key crypto.Signer, cert *x509.Certificate, keyID string) (ClientAuth, error) {
	return PrivateKeyJWTWithAlg(key, cert, keyID, "")
}

// ClientKeyType is a kind of client key and the algorithms it signs client assertions with, its
// default first.
type ClientKeyType struct {
	Name string // as in "an <Name> client key"
	Algs []string
}

// clientKeyTypes are the key types PrivateKeyJWTWithAlg signs with: RSA first, then EC P-256, since
// it picks a row by position; each row lists its default algorithm first.
var clientKeyTypes = []ClientKeyType{
	{Name: "RSA", Algs: []string{string(jose.PS256), string(jose.RS256)}}, // RS256 for an IdP that refuses PS256 (Okta, #306)
	{Name: "EC P-256", Algs: []string{string(jose.ES256)}},
}

// ClientKeyTypes are the client key types PrivateKeyJWTWithAlg accepts and the algorithms each signs
// with, for advice on what else to use (#306).
func ClientKeyTypes() []ClientKeyType {
	out := slices.Clone(clientKeyTypes)
	for i := range out {
		out[i].Algs = slices.Clone(out[i].Algs)
	}
	return out
}

// PrivateKeyJWTWithAlg is PrivateKeyJWT with the signing algorithm chosen: "" for the key type's
// default, else one of the algorithms ClientKeyTypes lists for it.
func PrivateKeyJWTWithAlg(key crypto.Signer, cert *x509.Certificate, keyID, algName string) (ClientAuth, error) {
	var kt ClientKeyType
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		kt = clientKeyTypes[0]
	case *ecdsa.PublicKey:
		if k.Curve.Params().Name != "P-256" {
			return nil, errors.New("idp: EC client keys must use P-256")
		}
		kt = clientKeyTypes[1]
	default:
		return nil, fmt.Errorf("idp: unsupported client key type %T", k)
	}
	if algName == "" {
		algName = kt.Algs[0]
	}
	if !slices.Contains(kt.Algs, algName) {
		return nil, fmt.Errorf("%w: an %s client key signs with %s, not %q", ErrClientKeyAlg, kt.Name, strings.Join(kt.Algs, " or "), algName)
	}
	alg := jose.SignatureAlgorithm(algName)
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
	return privateKeyJWT{signer: s, alg: alg, keyID: keyID}, nil
}

// SigningAlgorithm is the client assertion's JWS algorithm.
func (p privateKeyJWT) SigningAlgorithm() string { return string(p.alg) }

// KeyID is the assertion's `kid`, "" when there is none.
func (p privateKeyJWT) KeyID() string { return p.keyID }

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

// ParsePrivateKey reads one PEM private key for PrivateKeyJWT: PKCS #8, PKCS #1 (RSA) or SEC 1 (EC).
func ParsePrivateKey(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("a PEM %q block is not a private key", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("the private key does not parse: %w", err)
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("the private key cannot sign")
	}
	return s, nil
}
