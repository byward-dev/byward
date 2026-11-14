// Package testcert issues serving certificates for tests: a leaf under a fresh root, optionally
// through an intermediate, as the PEM files an operator would mount.
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Validity is a certificate's NotBefore and NotAfter.
type Validity struct{ NotBefore, NotAfter time.Time }

// Options shape the leaf. The root is valid from ten years ago to ten years ahead.
type Options struct {
	Hosts []string // DNS names and IP addresses in the leaf's SANs
	Leaf  Validity
	// Intermediate, when set, issues the leaf through an intermediate CA valid for that time, and
	// the certificate file lists it after the leaf.
	Intermediate *Validity
}

// Bundle is an issued certificate: the certificate file (leaf, then any intermediate), its key
// file, and the root, as a pool for clients and as the PEM file a client is pointed at.
type Bundle struct {
	Cert, Key []byte
	Roots     *x509.CertPool
	RootPEM   []byte
}

// Valid is a validity around now: from an hour ago to days ahead.
func Valid(now time.Time, days int) Validity {
	return Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Duration(days) * 24 * time.Hour)}
}

// Issue issues a leaf for o.
func Issue(t testing.TB, o Options) Bundle {
	t.Helper()
	root, rootKey := newRoot(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	parent, parentKey := root, rootKey
	var chain []byte
	if o.Intermediate != nil {
		parent, parentKey = issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Test Intermediate"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: o.Intermediate.NotBefore, NotAfter: o.Intermediate.NotAfter}, root, rootKey)
		chain = certPEM(parent)
	}
	leafTmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Test Leaf"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: o.Leaf.NotBefore, NotAfter: o.Leaf.NotAfter}
	for _, h := range o.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTmpl.IPAddresses = append(leafTmpl.IPAddresses, ip)
		} else {
			leafTmpl.DNSNames = append(leafTmpl.DNSNames, h)
		}
	}
	leaf, leafKey := issue(t, leafTmpl, parent, parentKey)
	der, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{
		Cert:    append(certPEM(leaf), chain...),
		Key:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		Roots:   pool,
		RootPEM: certPEM(root),
	}
}

// Root returns a fresh root that issued nothing, in PEM: another CA, which a client pointed at it
// must refuse every Bundle's leaf under.
func Root(t testing.TB) []byte {
	t.Helper()
	root, _ := newRoot(t)
	return certPEM(root)
}

// newRoot makes a root valid from ten years ago to ten years ahead.
func newRoot(t testing.TB) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Test Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.AddDate(-10, 0, 0), NotAfter: now.AddDate(10, 0, 0)}, nil, nil)
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// Write writes the bundle's files into dir as tls.crt and tls.key (mode 0600) and returns their
// paths.
func (b Bundle) Write(t testing.TB, dir string) (cert, key string) {
	t.Helper()
	cert, key = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for p, content := range map[string][]byte{cert: b.Cert, key: b.Key} {
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

var serial atomic.Int64

// issue signs tmpl with parentKey as parent, or self-signs it when parent is nil.
func issue(t testing.TB, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}
