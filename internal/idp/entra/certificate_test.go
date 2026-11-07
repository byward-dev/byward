package entra

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The file byward init entra writes, and each way a file can be unusable: refused at startup with
// a reason, never quoting the file. Expiry is not this check's: an expired certificate loads, for
// doctor to report and for revoke-user, which needs no credential.
func TestACertificateFileIsReadOrRefusedWithItsReason(t *testing.T) {
	key, other := rsaKey(t, 2048), rsaKey(t, 2048)
	year := now().Add(365 * 24 * time.Hour)
	cert := fakeidp.SelfSignedPEM(t, key, year)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	small := rsaKey(t, 1024)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := fakeidp.PrivateKeyPEM(t, key)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for name, tc := range map[string]struct {
		file []byte
		want string // "" accepts
	}{
		"key then certificate":              {cat(keyPEM, cert), ""},
		"certificate then key":              {cat(cert, keyPEM), ""},
		"a PKCS#1 key":                      {cat(pkcs1, cert), ""},
		"a chain, another one first":        {cat(fakeidp.SelfSignedPEM(t, other, year), keyPEM, cert), ""},
		"an expired certificate":            {cat(keyPEM, fakeidp.SelfSignedPEM(t, key, now().Add(-time.Hour))), ""},
		"no key":                            {cert, "no PEM private key"},
		"two keys":                          {cat(keyPEM, fakeidp.PrivateKeyPEM(t, other), cert), "2 private keys"},
		"no certificate":                    {keyPEM, "no PEM certificate"},
		"an encrypted PKCS#8 key":           {cat(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}), cert), "encrypted"},
		"a legacy encrypted key":            {cat(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}}), cert), "encrypted"},
		"an EC key":                         {cat(fakeidp.PrivateKeyPEM(t, ec), fakeidp.SelfSignedPEM(t, ec, year)), "an EC key: Entra accepts only RSA"},
		"an Ed25519 key":                    {cat(fakeidp.PrivateKeyPEM(t, ed), fakeidp.SelfSignedPEM(t, ed, year)), "an Ed25519 key: Entra accepts only RSA"},
		"a 1024-bit key":                    {cat(fakeidp.PrivateKeyPEM(t, small), fakeidp.SelfSignedPEM(t, small, year)), "1024-bit RSA key: use at least 2048"},
		"a certificate for another key":     {cat(keyPEM, fakeidp.SelfSignedPEM(t, other, year)), "no certificate in the file is for its private key"},
		"a certificate that does not parse": {cat(keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})), "a certificate does not parse"},
		"not PEM at all":                    {[]byte("s3cret"), "no PEM private key"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := LoadCertificate(tc.file)
			switch {
			case tc.want == "" && (err != nil || !c.Key.PublicKey.Equal(&key.PublicKey) || !c.X509.PublicKey.(*rsa.PublicKey).Equal(&key.PublicKey)):
				t.Fatalf("refused or wrong pair: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			case err != nil && (strings.Contains(err.Error(), "MII") || strings.Contains(err.Error(), "s3cret")):
				t.Fatalf("the error quotes the file: %v", err)
			}
		})
	}
}

// A loaded certificate signs Entra's client assertion: the fake IdP accepts it by x5t#S256, as
// Entra does, and the sign-in completes.
func TestALoadedCertificateSignsInAtEntra(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	c, err := LoadCertificate(cert.PEM(t))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := c.ClientAuth()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, Config{ClientAuth: ca, Now: time.Now})
	client := e.client
	client.Secrets, client.Certificates = nil, []*fakeidp.Certificate{cert}
	e.fake.Set(fakeidp.WithClient(client), fakeidp.WithClock(time.Now))
	if _, _, err := callback(t, e); err != nil {
		t.Fatal(err)
	}
}
