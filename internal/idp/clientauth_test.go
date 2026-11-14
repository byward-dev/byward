package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// A private_key_jwt key is read from PKCS #8, PKCS #1 or SEC 1 PEM; anything else is refused.
func TestAPrivateKeyIsReadFromPEMInItsUsualFormats(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
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
		raw  []byte
		want string // the error's start: a parse error appends the x509 package's reason
	}{
		"not PEM":       {[]byte("s3cret"), "not a PEM private key"},
		"a certificate": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), `a PEM "CERTIFICATE" block is not a private key`},
		"broken":        {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "the private key does not parse: "},
	} {
		if _, err := ParsePrivateKey(tc.raw); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
