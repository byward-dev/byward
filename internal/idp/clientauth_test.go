package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	for name, raw := range map[string][]byte{
		"not PEM":       []byte("s3cret"),
		"a certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"broken":        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := ParsePrivateKey(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
