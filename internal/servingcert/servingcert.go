// Package servingcert is the public listener's TLS certificate (#183): the operator's certificate
// and key files, checked when they are read and read again when they change, so a renewed
// certificate is served from the next handshake on, with no restart.
package servingcert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// leeway is how far in the future a certificate's NotBefore may be and still be served: a freshly
// issued certificate starts at its issuer's clock, which may run ahead of ours.
const leeway = 5 * time.Minute

// Files are the certificate file (the PEM certificate, then any intermediates) and its key file.
type Files struct{ Cert, Key string }

// Pair is a certificate and key that match, with the certificate chain parsed.
type Pair struct {
	cert *tls.Certificate
	// chain is the leaf first, then the intermediates, as the certificate file lists them.
	chain []*x509.Certificate
}

// Read reads and parses f. Errors name the file at fault and never quote either file.
func Read(f Files) (*Pair, error) {
	certPEM, err := os.ReadFile(f.Cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(f.Key)
	if err != nil {
		return nil, err
	}
	if encrypted(keyPEM) { // it would fail below with an ASN.1 error that does not say why
		return nil, fmt.Errorf("%s: the private key is encrypted; give the key unencrypted and protect the file instead", f.Key)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s and %s: %w", f.Cert, f.Key, err)
	}
	p := &Pair{cert: &cert}
	for _, der := range cert.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Cert, err)
		}
		p.chain = append(p.chain, c)
	}
	return p, nil
}

// encrypted reports whether a PEM file holds an encrypted private key: PKCS#8's ENCRYPTED PRIVATE
// KEY, or a legacy key with a Proc-Type: 4,ENCRYPTED header.
func encrypted(pemData []byte) bool {
	for {
		var b *pem.Block
		if b, pemData = pem.Decode(pemData); b == nil {
			return false
		}
		if b.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
			return true
		}
	}
}

// notYetValidError is a certificate in the chain whose NotBefore is more than leeway away.
type notYetValidError struct {
	name      string
	notBefore time.Time
}

func (e *notYetValidError) Error() string {
	return fmt.Sprintf("%s is not valid until %s", e.name, e.notBefore.UTC().Format(time.RFC3339))
}

// Validity checks every certificate in the chain at now: any expired one is an error, and so is a
// NotBefore more than five minutes away.
func (p *Pair) Validity(now time.Time) error {
	var errs []error
	for i, c := range p.chain {
		switch {
		case now.After(c.NotAfter):
			errs = append(errs, fmt.Errorf("%s expired on %s", p.name(i), c.NotAfter.UTC().Format(time.RFC3339)))
		case c.NotBefore.After(now.Add(leeway)):
			errs = append(errs, &notYetValidError{name: p.name(i), notBefore: c.NotBefore})
		}
	}
	return errors.Join(errs...)
}

// ServableAt is when a pair Validity refused with err becomes servable, if err says only that
// certificates are not valid yet: five minutes before the latest of their NotBefore.
func ServableAt(err error) (time.Time, bool) {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok { //nolint:errorlint // the errors.Join list itself
		errs = j.Unwrap()
	}
	var at time.Time
	for _, e := range errs {
		var nyv *notYetValidError
		if !errors.As(e, &nyv) {
			return time.Time{}, false
		}
		if s := nyv.notBefore.Add(-leeway); s.After(at) {
			at = s
		}
	}
	return at, true
}

// FirstExpiry names the chain's certificate that expires first, and when.
func (p *Pair) FirstExpiry() (name string, notAfter time.Time) {
	first := 0
	for i, c := range p.chain {
		if c.NotAfter.Before(p.chain[first].NotAfter) {
			first = i
		}
	}
	return p.name(first), p.chain[first].NotAfter
}

// name names the chain's certificate i for an operator: its place in the chain and its subject.
func (p *Pair) name(i int) string {
	place := "the certificate"
	if i > 0 {
		place = fmt.Sprintf("chain certificate %d", i+1)
	}
	return fmt.Sprintf("%s (%s)", place, p.chain[i].Subject)
}

// Covers reports whether the certificate is valid for host (no port), by its SANs.
func (p *Pair) Covers(host string) bool { return p.chain[0].VerifyHostname(host) == nil }
