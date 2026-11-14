package doctor

import (
	"cmp"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
// SSL_CERT_FILE or SSL_CERT_DIR entry it cannot read or that holds no certificate it accepts, drops
// the public roots when the settings reach none of them, and ignores both settings under GODEBUG
// x509sslcertoverrideplatform=0: each is a warning (#327 for the directories). read reads a file;
// list lists a directory as Go does (CertDirEntries).
func TrustStore(s TrustSettings, read func(string) ([]byte, error), list func(string) ([]string, error)) Result {
	r := CheckTrustStore.Result(Pass, "", "")
	if s.SettingsIgnored {
		r.Message = "roots from the system's verifier"
		if s.CertFile != "" || s.CertDir != "" {
			r.Status, r.Message = Warn, "GODEBUG x509sslcertoverrideplatform=0 keeps the system's verifier, so Go ignores SSL_CERT_FILE and SSL_CERT_DIR"
			r.Fix = "add your CA to the system's trust store, or remove x509sslcertoverrideplatform=0 from GODEBUG (docs/how-to/private-ca.md)"
		}
		return r
	}
	var from, problems, fixes []string
	file := 0 // the certificates Go reads from SSL_CERT_FILE
	fileErr := false
	if s.CertFile != "" {
		data, err := read(s.CertFile)
		switch n := countCertificates(data); {
		case err != nil:
			problems = append(problems, fmt.Sprintf("SSL_CERT_FILE %s cannot be read (%v), so Go reads nothing from it", s.CertFile, err))
			fixes = append(fixes, "mount the CA file at that path, readable by byward's user, or unset SSL_CERT_FILE")
			fileErr = !errors.Is(err, fs.ErrNotExist)
		case n == 0:
			problems = append(problems, fmt.Sprintf("SSL_CERT_FILE %s holds no PEM certificate Go accepts, so Go reads nothing from it", s.CertFile))
			fixes = append(fixes, "put the CA's PEM certificate (-----BEGIN CERTIFICATE-----, no headers) in that file")
		default:
			file = n
			from = append(from, fmt.Sprintf("SSL_CERT_FILE %s (%d certificate(s))", s.CertFile, n))
		}
	}
	d := readCertDirs(s.CertDir, read, list)
	if len(d.problems) > 0 {
		problems = append(problems, d.problems...)
		fixes = append(fixes, "make each SSL_CERT_DIR entry a directory of PEM certificates that byward's user can read, or remove the entry")
	}
	skipped := ""
	if len(d.missing) > 0 && len(d.missing) < len(filepath.SplitList(s.CertDir)) { // none at all is a problem of its own
		skipped = "Go skips the missing entries " + strings.Join(d.missing, ", ")
		if len(d.missing) == 1 {
			skipped = "Go skips the missing entry " + d.missing[0]
		}
	}
	if d.certs > 0 {
		note := ""
		if skipped != "" {
			note = "; " + skipped
		}
		from = append(from, fmt.Sprintf("SSL_CERT_DIR %s (%d certificate(s)%s)", s.CertDir, d.certs, note))
	}
	if len(problems) > 0 {
		if skipped != "" {
			problems = append(problems, skipped)
		}
		r.Status, r.Message = Warn, strings.Join(problems, "; ")+", and "+trusted(s, file, d, fileErr)
		r.Fix = strings.Join(fixes, "; ") + " (docs/how-to/private-ca.md)"
		return r
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

// certDirs is what Go reads from the SSL_CERT_DIR list: the certificates it accepts, whether an
// entry failed other than by not existing (Go then falls back to a platform verifier when no root
// loads), what is wrong with the entries, those Go skips because they do not exist, and those that
// yield a certificate.
type certDirs struct {
	certs    int
	err      bool
	problems []string
	missing  []string
	yielded  []string // the entries that hold a certificate
}

// readCertDirs reads the SSL_CERT_DIR list as Go does (crypto/x509, loadOnDiskRoots): an entry that
// does not exist is skipped silently, any other error is kept, and every file of a directory is
// read, its errors ignored. An entry that cannot be read or holds no certificate is a problem, and
// so is a list of which no entry exists.
func readCertDirs(dirs string, read func(string) ([]byte, error), list func(string) ([]string, error)) certDirs {
	var d certDirs
	if dirs == "" {
		return d
	}
	entries := filepath.SplitList(dirs)
	for _, dir := range entries {
		names, err := list(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			d.missing = append(d.missing, cmp.Or(dir, `""`)) // an empty entry, as in a trailing ":", is named visibly
			continue
		case err != nil:
			d.err = true
			d.problems = append(d.problems, fmt.Sprintf("SSL_CERT_DIR entry %s cannot be read as a directory (%v), so Go reads nothing from it", dir, err))
			continue
		}
		n := 0
		for _, name := range names {
			data, _ := read(filepath.Join(dir, name))
			n += countCertificates(data)
		}
		if n == 0 {
			d.problems = append(d.problems, fmt.Sprintf("SSL_CERT_DIR entry %s holds no PEM certificate Go accepts, so Go reads nothing from it", dir))
		} else {
			d.yielded = append(d.yielded, dir)
		}
		d.certs += n
	}
	if len(d.missing) == len(entries) {
		d.problems = append(d.problems, fmt.Sprintf("no SSL_CERT_DIR entry exists (%s), so Go reads no directory", strings.Join(d.missing, ", ")))
	}
	return d
}

// trusted is what Go trusts when a setting yields less than it should (crypto/x509, root.go): the
// file's and the directories' certificates, the public roots where the settings leave them in, or,
// on a platform verifier, that verifier again when nothing loads and something failed other than by
// not existing (fileErr, d.err).
func trusted(s TrustSettings, file int, d certDirs, fileErr bool) string {
	var parts []string
	if file > 0 {
		parts = append(parts, "SSL_CERT_FILE "+s.CertFile)
	}
	switch len(d.yielded) {
	case 0:
	case 1:
		parts = append(parts, "SSL_CERT_DIR entry "+d.yielded[0])
	default:
		parts = append(parts, "SSL_CERT_DIR entries "+strings.Join(d.yielded, ", "))
	}
	switch {
	case s.PlatformVerifier && len(parts) == 0 && (fileErr || d.err):
		return "falls back to the system's verifier"
	case s.PlatformVerifier && len(parts) == 0:
		return "trusts no root at all"
	case s.PlatformVerifier:
		return "trusts only " + strings.Join(parts, " and ")
	case s.CertDir == "" && file == 0:
		return "trusts the public roots alone"
	case s.CertFile == "":
		parts = append([]string{"the public bundle"}, parts...)
	case len(parts) == 0:
		return "trusts no root at all"
	}
	if !keepsPublicRoots(s) {
		return "trusts only " + strings.Join(parts, " and ") + ": the public roots are dropped"
	}
	return "trusts only " + strings.Join(parts, " and ")
}

// CertDirEntries lists a directory as Go does for SSL_CERT_DIR (crypto/x509,
// readUniqueDirectoryEntries): every entry but a symlink to another entry of the same directory.
func CertDirEntries(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, de := range des {
		if de.Type()&fs.ModeSymlink != 0 {
			if target, err := os.Readlink(filepath.Join(dir, de.Name())); err == nil && !strings.ContainsRune(target, filepath.Separator) {
				continue
			}
		}
		names = append(names, de.Name())
	}
	return names, nil
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
