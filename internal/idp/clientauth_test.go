package idp

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// A private_key_jwt key is read from PKCS #8, PKCS #1 or SEC 1 PEM; anything else, or a key that
// cannot sign, is refused, saying why.
func TestAPrivateKeyIsReadFromPEMInItsUsualFormats(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := x509.MarshalPKCS8PrivateKey(x25519Key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"PKCS #8": {Type: "PRIVATE KEY", Bytes: pkcs8},
		"PKCS #1": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)},
		"SEC 1":   {Type: "EC PRIVATE KEY", Bytes: sec1},
	} {
		if _, err := ParsePrivateKey(pem.EncodeToMemory(block)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		raw    []byte
		want   string
		prefix bool // want is the error's start: a parse error appends the x509 package's reason
	}{
		"not PEM":       {raw: []byte("s3cret"), want: "not a PEM private key"},
		"a certificate": {raw: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), want: `a PEM "CERTIFICATE" block is not a private key`},
		"broken":        {raw: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), want: "the private key does not parse: ", prefix: true},
		"an X25519 key": {raw: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x25519}), want: "the private key cannot sign"},
	} {
		_, err := ParsePrivateKey(tc.raw)
		matches := err != nil && (err.Error() == tc.want || tc.prefix && strings.HasPrefix(err.Error(), tc.want))
		if !matches {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
