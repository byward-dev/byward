package entra

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/byward-dev/byward/internal/idp"
)

// MinRSABits is the smallest client key accepted: Microsoft "highly recommends" 2048 bits
// (learn.microsoft.com/entra/identity-platform/howto-create-self-signed-certificate).
const MinRSABits = 2048

// Certificate is the app's certificate credential (ADR-0012 §5): an RSA key and the certificate
// uploaded to the app registration for it.
type Certificate struct {
	Key  *rsa.PrivateKey
	X509 *x509.Certificate
}

// LoadCertificate reads a PEM file holding the private key and its certificate, as byward init
// entra writes it. The file must hold exactly one unencrypted private key, RSA ("Microsoft Entra
// ID currently supports only RSA") of at least MinRSABits, and a certificate for that key; other
// certificates (a chain) are allowed. Errors never quote the file. Expiry is not checked here: the
// proxy refuses to start with an expired certificate, while doctor reports it and revoke-user, which
// needs no credential, still works.
func LoadCertificate(raw []byte) (*Certificate, error) {
	var keys, certs []*pem.Block
	for rest := raw; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch {
		case b.Type == "CERTIFICATE":
			certs = append(certs, b)
		case b.Type == "ENCRYPTED PRIVATE KEY" || b.Headers["Proc-Type"] == "4,ENCRYPTED":
			return nil, errors.New("the private key is encrypted; byward needs it unencrypted, in a file only its user can read")
		case strings.HasSuffix(b.Type, "PRIVATE KEY"):
			keys = append(keys, b)
		}
	}
	switch {
	case len(keys) == 0:
		return nil, errors.New("no PEM private key: the file must hold the private key and its certificate")
	case len(keys) > 1:
		return nil, fmt.Errorf("%d private keys: the file must hold exactly one", len(keys))
	case len(certs) == 0:
		return nil, errors.New("no PEM certificate: the file must hold the certificate uploaded to the app registration, with its private key")
	}
	signer, err := idp.ParsePrivateKey(pem.EncodeToMemory(keys[0]))
	if err != nil {
		return nil, err
	}
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		kind := "non-RSA"
		switch signer.Public().(type) {
		case *ecdsa.PublicKey:
			kind = "EC"
		case ed25519.PublicKey:
			kind = "Ed25519"
		}
		return nil, fmt.Errorf("an %s key: Entra accepts only RSA certificate credentials", kind)
	}
	if n := key.N.BitLen(); n < MinRSABits {
		return nil, fmt.Errorf("a %d-bit RSA key: use at least %d bits", n, MinRSABits)
	}
	for _, b := range certs {
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a certificate does not parse: %w", err)
		}
		if pub, ok := c.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
			continue
		}
		return &Certificate{Key: key, X509: c}, nil
	}
	return nil, errors.New("no certificate in the file is for its private key")
}

// ClientAuth is the certificate as Entra's client assertion: PS256 with x5t#S256 (ADR-0012 §5).
func (c *Certificate) ClientAuth() (idp.ClientAuth, error) {
	return idp.PrivateKeyJWT(c.Key, c.X509, "")
}
