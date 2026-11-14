package doctor

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

// Where Linux keeps the public roots, as Go reads them by default (crypto/x509, root_linux.go): a
// bundle file is read when SSL_CERT_FILE is unset or names one of these, and every file in a public
// directory when SSL_CERT_DIR is unset or lists one of these.
var (
	publicBundles = []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"}
	publicCertsDirs = []string{"/etc/ssl/certs", "/etc/pki/tls/certs"}
)

// TrustSettings are what Go reads its roots from: SSL_CERT_FILE and SSL_CERT_DIR, whether the
// platform has a system verifier those replace (macOS, iOS, Windows), whether GODEBUG
// x509sslcertoverrideplatform=0 keeps that verifier so both settings are ignored, and the number of
// roots Go loaded (0 when unknown, as with that verifier).
type TrustSettings struct {
	CertFile, CertDir string
	PlatformVerifier  bool
	SettingsIgnored   bool
	RootCount         int
}

// TrustStore reports where the roots byward trusts for the IdP, an https upstream and client
// metadata documents (CIMD) come from (#308, docs/how-to/private-ca.md). Go silently ignores an
// SSL_CERT_FILE it cannot read or that holds no certificate it accepts, drops the public roots when
// the settings reach none of them, and ignores both settings under GODEBUG
// x509sslcertoverrideplatform=0: each is a warning. It does not read SSL_CERT_DIR's entries. read
// reads a file.
func TrustStore(s TrustSettings, read func(string) ([]byte, error)) Result {
	r := Result{Class: ClassProxy, Name: "trust store", Status: Pass}
	if s.SettingsIgnored {
		r.Message = "roots from the system's verifier"
		if s.CertFile != "" || s.CertDir != "" {
			r.Status, r.Message = Warn, "GODEBUG x509sslcertoverrideplatform=0 keeps the system's verifier, so Go ignores SSL_CERT_FILE and SSL_CERT_DIR"
			r.Fix = "add your CA to the system's trust store, or remove x509sslcertoverrideplatform=0 from GODEBUG (docs/how-to/private-ca.md)"
		}
		return r
	}
	var from []string
	if s.CertFile != "" {
		data, err := read(s.CertFile)
		switch n := countCertificates(data); {
		case err != nil:
			r.Status, r.Message = Warn, fmt.Sprintf("SSL_CERT_FILE %s cannot be read (%v), so Go reads nothing from it, and %s", s.CertFile, err,
				withoutFile(s, !errors.Is(err, fs.ErrNotExist)))
			r.Fix = "mount the CA file at that path, readable by byward's user, or unset SSL_CERT_FILE (docs/how-to/private-ca.md)"
			return r
		case n == 0:
			r.Status, r.Message = Warn, fmt.Sprintf("SSL_CERT_FILE %s holds no PEM certificate Go accepts, so Go reads nothing from it, and %s", s.CertFile, withoutFile(s, false))
			r.Fix = "put the CA's PEM certificate (-----BEGIN CERTIFICATE-----, no headers) in that file (docs/how-to/private-ca.md)"
			return r
		default:
			from = append(from, fmt.Sprintf("SSL_CERT_FILE %s (%d certificate(s))", s.CertFile, n))
		}
	}
	if s.CertDir != "" {
		from = append(from, "SSL_CERT_DIR "+s.CertDir)
	}
	if s.PlatformVerifier && len(from) > 0 {
		r.Status, r.Message = Warn, "SSL_CERT_FILE or SSL_CERT_DIR replaces the system's verifier here, so Go trusts only "+strings.Join(from, " and ")
		r.Fix = "add your CA to the system's trust store instead, and unset SSL_CERT_FILE and SSL_CERT_DIR (docs/how-to/private-ca.md)"
		return r
	}
	if !keepsPublicRoots(s) { // a platform verifier with either setting was warned of above
		r.Status = Warn
		r.Message = fmt.Sprintf("SSL_CERT_FILE names %s and SSL_CERT_DIR %s lists neither %s, so Go reads only that file and those directories: the public roots are dropped unless that file holds them",
			s.CertFile, s.CertDir, strings.Join(publicCertsDirs, " nor "))
		r.Fix = "add :/etc/ssl/certs to SSL_CERT_DIR, or set only one of SSL_CERT_FILE and SSL_CERT_DIR (docs/how-to/private-ca.md)"
		return r
	}
	switch {
	case len(from) > 0:
	case s.PlatformVerifier:
		from = append(from, "the system's verifier")
	default:
		from = append(from, "the system's default locations")
	}
	r.Message = "roots from " + strings.Join(from, " and ")
	if s.RootCount > 0 {
		r.Message += fmt.Sprintf(": %d in all", s.RootCount)
	}
	return r
}

// withoutFile is what Go trusts when it reads nothing from SSL_CERT_FILE (crypto/x509, root.go). A
// platform verifier is replaced all the same, unless the file existed but could not be read
// (unreadable) and nothing else yields a root: Go then falls back to that verifier. On Linux the
// directories alone are read: SSL_CERT_DIR's, or the public ones.
func withoutFile(s TrustSettings, unreadable bool) string {
	switch {
	case s.PlatformVerifier && unreadable && s.CertDir == "":
		return "falls back to the system's verifier"
	case s.PlatformVerifier && unreadable:
		return "trusts only SSL_CERT_DIR " + s.CertDir + ", or the system's verifier if that holds no certificate"
	case s.PlatformVerifier && s.CertDir == "":
		return "trusts no root at all"
	case s.CertDir != "" && !s.PlatformVerifier && !listsPublicDir(s.CertDir):
		return "trusts only SSL_CERT_DIR " + s.CertDir + ": the public roots are dropped"
	case s.CertDir != "":
		return "trusts only SSL_CERT_DIR " + s.CertDir
	}
	return "trusts the public roots alone"
}

// keepsPublicRoots reports whether Go, on Linux, still reads a public bundle or directory: with
// SSL_CERT_FILE unset or naming a public bundle, or SSL_CERT_DIR unset or listing a public directory.
func keepsPublicRoots(s TrustSettings) bool {
	return s.CertFile == "" || slices.Contains(publicBundles, filepath.Clean(s.CertFile)) || s.CertDir == "" || listsPublicDir(s.CertDir)
}

// listsPublicDir reports whether the SSL_CERT_DIR list holds a public directory.
func listsPublicDir(dirs string) bool {
	return slices.ContainsFunc(filepath.SplitList(dirs), func(d string) bool { return slices.Contains(publicCertsDirs, filepath.Clean(d)) })
}

// countCertificates is the number of PEM certificates in data that Go accepts as roots: blocks of
// type CERTIFICATE without headers that parse (crypto/x509, CertPool.AppendCertsFromPEM).
func countCertificates(data []byte) int {
	n := 0
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return n
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			continue
		}
		if _, err := x509.ParseCertificate(b.Bytes); err == nil {
			n++
		}
	}
}
