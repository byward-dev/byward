package fakeidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as a SHA-1 thumbprint (RFC 7517 §4.8).
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

// Certificate is an RSA key with a self-signed certificate, used for the fake's signing keys and
// for clients' private_key_jwt credentials.
type Certificate struct {
	Key  *rsa.PrivateKey
	X509 *x509.Certificate
}

// NewCertificate generates a 2048-bit RSA key and a self-signed certificate valid for a day
// around now.
func NewCertificate(t testing.TB) *Certificate {
	t.Helper()
	c, err := newCertificate(time.Now())
	if err != nil {
		t.Fatalf("fakeidp: certificate: %v", err)
	}
	return c
}

func newCertificate(now time.Time) (*Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fakeidp"},
		NotBefore:    now.Add(-12 * time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Certificate{Key: key, X509: cert}, nil
}

// ThumbprintSHA1 is the `x5t` header value for this certificate.
func (c *Certificate) ThumbprintSHA1() string {
	sum := sha1.Sum(c.X509.Raw) //nolint:gosec // x5t is SHA-1 by definition.
	return b64.EncodeToString(sum[:])
}

// ThumbprintSHA256 is the `x5t#S256` header value for this certificate.
func (c *Certificate) ThumbprintSHA256() string {
	sum := sha256.Sum256(c.X509.Raw)
	return b64.EncodeToString(sum[:])
}

// SignJWT signs claims with this key. alg is RS256 or PS256; extra header fields (e.g. x5t#S256)
// are merged into the header.
func (c *Certificate) SignJWT(alg string, header, claims map[string]any) (string, error) {
	h := map[string]any{"alg": alg, "typ": "JWT"}
	for k, v := range header {
		h[k] = v
	}
	return signRSA(c.Key, alg, h, claims)
}

type signingKey struct {
	cert *Certificate
	kid  string
}

func newSigningKey(now time.Time) (*signingKey, error) {
	c, err := newCertificate(now)
	if err != nil {
		return nil, err
	}
	// Entra uses the SHA-1 thumbprint as both kid and x5t.
	return &signingKey{cert: c, kid: c.ThumbprintSHA1()}, nil
}

func (k *signingKey) sign(claims map[string]any) string {
	s, err := signRSA(k.cert.Key, "RS256", map[string]any{"alg": "RS256", "typ": "JWT", "kid": k.kid, "x5t": k.kid}, claims)
	if err != nil {
		panic(fmt.Sprintf("fakeidp: sign: %v", err)) // only fails on a broken key or unmarshalable claims
	}
	return s
}

func (k *signingKey) jwk(issuer string) map[string]any {
	pub := &k.cert.Key.PublicKey
	m := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": k.kid,
		"x5t": k.kid,
		"n":   b64.EncodeToString(pub.N.Bytes()),
		"e":   b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		"x5c": []string{base64.StdEncoding.EncodeToString(k.cert.X509.Raw)},
	}
	if issuer != "" {
		m["issuer"] = issuer
	}
	return m
}

func signRSA(key *rsa.PrivateKey, alg string, header, claims map[string]any) (string, error) {
	hj, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hj) + "." + b64.EncodeToString(cj)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		return "", fmt.Errorf("unsupported alg %q", alg)
	}
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

type jws struct {
	header map[string]any
	claims map[string]any
	input  []byte
	sig    []byte
}

func parseJWS(s string) (*jws, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	var j jws
	for i, dst := range []*map[string]any{&j.header, &j.claims} {
		raw, err := b64.DecodeString(parts[i])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return nil, err
		}
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	j.input = []byte(parts[0] + "." + parts[1])
	j.sig = sig
	return &j, nil
}

func (j *jws) str(k string) string {
	v, _ := j.header[k].(string)
	return v
}

func (j *jws) verify(pub *rsa.PublicKey, allowed ...string) error {
	alg := j.str("alg")
	sum := sha256.Sum256(j.input)
	for _, a := range allowed {
		if a != alg {
			continue
		}
		switch alg {
		case "RS256":
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], j.sig)
		case "PS256":
			return rsa.VerifyPSS(pub, crypto.SHA256, sum[:], j.sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		}
	}
	return fmt.Errorf("alg %q not allowed", alg)
}

// NewGUID returns a random version-4 GUID, for tenant, object and client IDs in fixtures.
func NewGUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}

func randomToken() string { return rand.Text() + rand.Text() }

func audContains(aud any, want ...string) bool {
	switch v := aud.(type) {
	case string:
		return slices.Contains(want, v)
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && slices.Contains(want, s) {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// NewCertificateUntil is NewCertificate with a certificate valid until notAfter (in the past for an
// expired one), and for 400 days before it.
func NewCertificateUntil(t testing.TB, notAfter time.Time) *Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(selfSignedDER(t, key, notAfter))
	if err != nil {
		t.Fatal(err)
	}
	return &Certificate{Key: key, X509: cert}
}

// PEM is the key (PKCS#8) and the certificate in one PEM file, as byward's Entra certificate
// credential reads them.
func (c *Certificate) PEM(t testing.TB) []byte {
	t.Helper()
	return append(PrivateKeyPEM(t, c.Key), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.X509.Raw})...)
}

// SelfSignedPEM is a self-signed certificate for key (of any type), valid until notAfter and for 400
// days before it, as a PEM block.
func SelfSignedPEM(t testing.TB, key crypto.Signer, notAfter time.Time) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedDER(t, key, notAfter)})
}

// PrivateKeyPEM is key as a PKCS#8 PEM block.
func PrivateKeyPEM(t testing.TB, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func selfSignedDER(t testing.TB, key crypto.Signer, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "byward-test"}, NotBefore: notAfter.Add(-400 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
