package doctor

import (
	"encoding/pem"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// The trust store line (#308): where Go's roots come from, and a warning for each setting Go
// silently ignores or that drops the public roots, as measured in the image and on macOS
// (docs/how-to/private-ca.md).
func TestTheTrustStoreLineSaysWhereTheRootsComeFrom(t *testing.T) {
	der := fakeidp.NewCertificate(t).X509.Raw
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	files := map[string][]byte{
		"/etc/byward/ca.pem":                                ca,
		"/etc/byward/two.pem":                               append(append([]byte{}, ca...), ca...),
		"/etc/byward/key.pem":                               []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"/etc/byward/text.txt":                              []byte("not a certificate"),
		"/etc/byward/trusted.pem":                           pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: der}),
		"/etc/byward/headers.pem":                           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der}),
		"/etc/byward/junk.pem":                              pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		"/etc/ssl/certs/private-ca.pem":                     ca,
		"/etc/ssl/certs/../../byward/ca.pem":                ca,
		"/etc/ssl/certsX/ca.pem":                            ca,
		"/etc/ssl/certs/ca-certificates.crt":                ca,
		"/etc/pki/tls/certs/ca-bundle.crt":                  ca,
		"/etc/ssl/ca-bundle.pem":                            ca,
		"/etc/pki/tls/cacert.pem":                           ca,
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem": ca,
		"/etc/ssl/cert.pem":                                 ca,
		"/etc/ssl/certs/./ca-certificates.crt":              ca,
		"/etc/byward/key-then-ca.pem":                       append([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), ca...),
	}
	read := func(name string) ([]byte, error) {
		if name == "/etc/byward/adir" {
			return nil, &fs.PathError{Op: "read", Path: name, Err: syscall.EISDIR} // neither not-exist nor permission
		}
		if name == "/etc/byward/noperm.pem" {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission} // as os.ReadFile wraps it
		}
		if b, ok := files[name]; ok {
			return b, nil
		}
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	const dropped = "lists neither /etc/ssl/certs nor /etc/pki/tls/certs, so Go reads only that file and those directories: the public roots are dropped unless that file holds them"
	for _, tc := range []struct {
		name    string
		s       TrustSettings
		status  Status
		message string // the whole message of a pass; a part of a warning's
		fix     string // a part of a warning's fix; a pass has none
	}{
		{"nothing set", TrustSettings{RootCount: 148}, Pass, "roots from the system's default locations: 148 in all", ""},
		{"a CA file", TrustSettings{CertFile: "/etc/byward/ca.pem", RootCount: 149}, Pass, "roots from SSL_CERT_FILE /etc/byward/ca.pem (1 certificate(s)): 149 in all", ""},
		{"a file with two certificates and no root count", TrustSettings{CertFile: "/etc/byward/two.pem"}, Pass, "roots from SSL_CERT_FILE /etc/byward/two.pem (2 certificate(s))", ""},
		{"a file that does not exist", TrustSettings{CertFile: "/etc/byward/missing.pem"}, Warn,
			"SSL_CERT_FILE /etc/byward/missing.pem cannot be read (open /etc/byward/missing.pem: file does not exist), so Go reads nothing from it, and trusts the public roots alone", "mount the CA file at that path"},
		{"a file that does not exist, and a directory without the public roots", TrustSettings{CertFile: "/etc/byward/missing.pem", CertDir: "/etc/byward"}, Warn,
			"so Go reads nothing from it, and trusts only SSL_CERT_DIR /etc/byward: the public roots are dropped", "mount the CA file at that path"},
		{"a file that does not exist, on a platform verifier", TrustSettings{CertFile: "/etc/byward/missing.pem", PlatformVerifier: true}, Warn,
			"so Go reads nothing from it, and trusts no root at all", "mount the CA file at that path"},
		{"a file that cannot be read, on a platform verifier", TrustSettings{CertFile: "/etc/byward/noperm.pem", PlatformVerifier: true}, Warn,
			"cannot be read (open /etc/byward/noperm.pem: permission denied), so Go reads nothing from it, and falls back to the system's verifier", "mount the CA file at that path"},
		{"a file that cannot be read, and a directory, on a platform verifier", TrustSettings{CertFile: "/etc/byward/noperm.pem", CertDir: "/etc/byward", PlatformVerifier: true}, Warn,
			"and trusts only SSL_CERT_DIR /etc/byward, or the system's verifier if that holds no certificate", ""},
		{"a file that does not exist, and a directory list with a public one", TrustSettings{CertFile: "/etc/byward/missing.pem", CertDir: "/etc/byward:/etc/ssl/certs"}, Warn,
			"so Go reads nothing from it, and trusts only SSL_CERT_DIR /etc/byward:/etc/ssl/certs", "mount the CA file at that path"},
		{"settings ignored through GODEBUG, a directory set", TrustSettings{CertDir: "/etc/byward/ca", SettingsIgnored: true}, Warn,
			"keeps the system's verifier, so Go ignores SSL_CERT_FILE and SSL_CERT_DIR", "remove x509sslcertoverrideplatform=0"},
		{"a file of no certificate, on a platform verifier", TrustSettings{CertFile: "/etc/byward/key.pem", PlatformVerifier: true}, Warn,
			"holds no PEM certificate Go accepts, so Go reads nothing from it, and trusts no root at all", ""},
		{"a file that is a directory, on a platform verifier", TrustSettings{CertFile: "/etc/byward/adir", PlatformVerifier: true}, Warn,
			"so Go reads nothing from it, and falls back to the system's verifier", ""},
		{"a file that cannot be read, on Linux", TrustSettings{CertFile: "/etc/byward/noperm.pem"}, Warn,
			"cannot be read (open /etc/byward/noperm.pem: permission denied), so Go reads nothing from it, and trusts the public roots alone", ""},
		{"a file that cannot be read, and a directory, on Linux", TrustSettings{CertFile: "/etc/byward/noperm.pem", CertDir: "/etc/byward"}, Warn,
			"so Go reads nothing from it, and trusts only SSL_CERT_DIR /etc/byward: the public roots are dropped", ""},
		{"settings ignored through GODEBUG, none set", TrustSettings{SettingsIgnored: true}, Pass, "roots from the system's verifier", ""},
		{"settings ignored through GODEBUG, a CA file set", TrustSettings{CertFile: "/etc/byward/ca.pem", SettingsIgnored: true}, Warn,
			"GODEBUG x509sslcertoverrideplatform=0 keeps the system's verifier, so Go ignores SSL_CERT_FILE and SSL_CERT_DIR", "remove x509sslcertoverrideplatform=0 from GODEBUG"},
		{"a file of no certificate, and a directory, on a platform verifier", TrustSettings{CertFile: "/etc/byward/key.pem", CertDir: "/etc/byward", PlatformVerifier: true}, Warn,
			"holds no PEM certificate Go accepts, so Go reads nothing from it, and trusts only SSL_CERT_DIR /etc/byward", "put the CA's PEM certificate"},
		{"a file of a key, not a certificate", TrustSettings{CertFile: "/etc/byward/key.pem"}, Warn, "holds no PEM certificate Go accepts, so Go reads nothing from it, and trusts the public roots alone", "put the CA's PEM certificate"},
		{"a file that is not PEM", TrustSettings{CertFile: "/etc/byward/text.txt"}, Warn, "holds no PEM certificate Go accepts", "put the CA's PEM certificate"},
		{"a certificate under another block type", TrustSettings{CertFile: "/etc/byward/trusted.pem"}, Warn, "holds no PEM certificate Go accepts", "put the CA's PEM certificate"},
		{"a certificate block with PEM headers", TrustSettings{CertFile: "/etc/byward/headers.pem"}, Warn, "holds no PEM certificate Go accepts", "no headers"},
		{"a certificate block that does not parse", TrustSettings{CertFile: "/etc/byward/junk.pem"}, Warn, "holds no PEM certificate Go accepts", "put the CA's PEM certificate"},
		{"a CA file and a directory without the public roots", TrustSettings{CertFile: "/etc/byward/ca.pem", CertDir: "/etc/byward/ca"}, Warn,
			"SSL_CERT_FILE names /etc/byward/ca.pem and SSL_CERT_DIR /etc/byward/ca " + dropped, "add :/etc/ssl/certs to SSL_CERT_DIR"},
		{"a CA file kept in /etc/ssl/certs, and another directory", TrustSettings{CertFile: "/etc/ssl/certs/private-ca.pem", CertDir: "/etc/byward"}, Warn, dropped, ""},
		{"a CA file named through /etc/ssl/certs/..", TrustSettings{CertFile: "/etc/ssl/certs/../../byward/ca.pem", CertDir: "/etc/byward/ca"}, Warn, dropped, ""},
		{"a CA file in a directory that only starts like the public one", TrustSettings{CertFile: "/etc/ssl/certsX/ca.pem", CertDir: "/etc/byward/ca"}, Warn, dropped, ""},
		{"a directory alone: Go still reads the bundle file", TrustSettings{CertDir: "/etc/byward/ca"}, Pass, "roots from SSL_CERT_DIR /etc/byward/ca", ""},
		{"the image's own bundle setting and a directory", TrustSettings{CertFile: "/etc/ssl/certs/ca-certificates.crt", CertDir: "/etc/byward/ca"}, Pass,
			"roots from SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt (1 certificate(s)) and SSL_CERT_DIR /etc/byward/ca", ""},
		{"a file whose first block is not a certificate", TrustSettings{CertFile: "/etc/byward/key-then-ca.pem"}, Pass, "roots from SSL_CERT_FILE /etc/byward/key-then-ca.pem (1 certificate(s))", ""},
		{"the image's bundle, written with /./, and a directory", TrustSettings{CertFile: "/etc/ssl/certs/./ca-certificates.crt", CertDir: "/etc/byward"}, Pass,
			"roots from SSL_CERT_FILE /etc/ssl/certs/./ca-certificates.crt (1 certificate(s)) and SSL_CERT_DIR /etc/byward", ""},
		{"a SUSE bundle and a directory", TrustSettings{CertFile: "/etc/ssl/ca-bundle.pem", CertDir: "/etc/byward"}, Pass,
			"roots from SSL_CERT_FILE /etc/ssl/ca-bundle.pem (1 certificate(s)) and SSL_CERT_DIR /etc/byward", ""},
		{"an OpenELEC bundle and a directory", TrustSettings{CertFile: "/etc/pki/tls/cacert.pem", CertDir: "/etc/byward"}, Pass,
			"roots from SSL_CERT_FILE /etc/pki/tls/cacert.pem (1 certificate(s)) and SSL_CERT_DIR /etc/byward", ""},
		{"a CentOS 7 bundle and a directory", TrustSettings{CertFile: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", CertDir: "/etc/byward"}, Pass,
			"roots from SSL_CERT_FILE /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem (1 certificate(s)) and SSL_CERT_DIR /etc/byward", ""},
		{"an Alpine bundle and a directory", TrustSettings{CertFile: "/etc/ssl/cert.pem", CertDir: "/etc/byward"}, Pass,
			"roots from SSL_CERT_FILE /etc/ssl/cert.pem (1 certificate(s)) and SSL_CERT_DIR /etc/byward", ""},
		{"a RHEL bundle and a directory", TrustSettings{CertFile: "/etc/pki/tls/certs/ca-bundle.crt", CertDir: "/etc/byward"}, Pass,
			"roots from SSL_CERT_FILE /etc/pki/tls/certs/ca-bundle.crt (1 certificate(s)) and SSL_CERT_DIR /etc/byward", ""},
		{"a CA file and a RHEL public directory", TrustSettings{CertFile: "/etc/byward/ca.pem", CertDir: "/etc/byward:/etc/pki/tls/certs"}, Pass,
			"roots from SSL_CERT_FILE /etc/byward/ca.pem (1 certificate(s)) and SSL_CERT_DIR /etc/byward:/etc/pki/tls/certs", ""},
		{"the public directory with a trailing slash", TrustSettings{CertFile: "/etc/byward/ca.pem", CertDir: "/etc/ssl/certs/:/etc/byward/ca"}, Pass,
			"roots from SSL_CERT_FILE /etc/byward/ca.pem (1 certificate(s)) and SSL_CERT_DIR /etc/ssl/certs/:/etc/byward/ca", ""},
		{"a CA file on a platform verifier", TrustSettings{CertFile: "/etc/byward/ca.pem", PlatformVerifier: true}, Warn,
			"replaces the system's verifier here, so Go trusts only SSL_CERT_FILE /etc/byward/ca.pem", "add your CA to the system's trust store"},
		{"a directory on a platform verifier", TrustSettings{CertDir: "/etc/byward/ca", PlatformVerifier: true}, Warn, "so Go trusts only SSL_CERT_DIR /etc/byward/ca", ""},
		{"nothing set on a platform verifier", TrustSettings{PlatformVerifier: true}, Pass, "roots from the system's verifier", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := TrustStore(tc.s, read)
			ok := r.Class == ClassProxy && r.Name == "trust store" && r.Status == tc.status
			if tc.status == Pass {
				ok = ok && r.Message == tc.message && r.Fix == ""
			} else {
				// A row that does not expect the public roots dropped must not get that warning either.
				ok = ok && strings.Contains(r.Message, tc.message) && strings.Contains(r.Fix, tc.fix) &&
					strings.Contains(tc.message, "dropped") == strings.Contains(r.Message, "dropped")
			}
			if !ok {
				t.Fatalf("result %+v; want %v with message %q and fix %q", r, tc.status, tc.message, tc.fix)
			}
		})
	}
}
