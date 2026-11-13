// Package pgtest runs PostgreSQL for tests: a container per pinned image, with TLS on and a
// certificate from a CA made for the test, so tests connect with sslmode=verify-full as production
// must (#227). It needs Docker and runs only when BYWARD_POSTGRES=1 (`mise run test:postgres`).
package pgtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Images are the versions the store is tested on: the oldest it claims (15) and the newest, pinned
// by digest. Dependabot does not see Go values: keep each at least 14 days old by Docker Hub's
// last-updated date when updating (ADR-0024 §5). 15.18: 2026-08-05; 18.4: 2026-08-06.
var Images = []struct{ Name, Image string }{
	{"15", "postgres:15.18@sha256:6eb0add3b77c081df18aa518ce43df58fdcc40f2e6d868a6fd08038dc7acd425"},
	{"18", "postgres:18.4@sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636"},
}

// startup bounds the image pull, initdb and the first connection.
const startup = 3 * time.Minute

// Server is one PostgreSQL container. Its certificate names 127.0.0.1 only.
type Server struct {
	Host, Port, Password string
	CAFile               string        // the CA that signed the server's certificate, for sslrootcert
	Admin                *pgxpool.Pool // the postgres database, for creating and dropping test databases
	container            string
}

// Require skips unless BYWARD_POSTGRES=1, and fails when it is set without Docker.
func Require(t *testing.T) {
	t.Helper()
	if os.Getenv("BYWARD_POSTGRES") != "1" {
		t.Skip("set BYWARD_POSTGRES=1 to run the PostgreSQL tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("BYWARD_POSTGRES=1 but docker is not available: %v", err)
	}
}

// Start runs image with TLS on and returns once it accepts a verify-full connection. The container
// is removed when the test ends.
func Start(t *testing.T, image string) *Server {
	t.Helper()
	dir := t.TempDir()
	// The container's root reads the files and copies them for the postgres user: world-readable
	// test data, including a key made for this test only.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: test certificates the container reads
		t.Fatal(err)
	}
	ca := NewCA(t, "byward test CA")
	certPEM, keyPEM := ca.Issue(t, "127.0.0.1")
	for name, data := range map[string][]byte{"ca.pem": ca.CertPEM, "server.crt": certPEM, "server.key": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil { //nolint:gosec // G306: read by the container
			t.Fatal(err)
		}
	}
	s := &Server{Host: "127.0.0.1", Password: randomHex(t), CAFile: filepath.Join(dir, "ca.pem"), container: "byward-postgres-" + randomHex(t)}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", s.container).Run() }) //nolint:gosec // G204: our own container name
	// PostgreSQL refuses a key readable by others: the entrypoint copies it with mode 0600 for the
	// postgres user before starting the server. Docker picks the host port.
	setup := "install -d -o postgres -m 0700 /run/byward-tls && " +
		"install -o postgres -m 0600 /tls/server.crt /tls/server.key /run/byward-tls/ && " +
		"exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/run/byward-tls/server.crt " +
		"-c ssl_key_file=/run/byward-tls/server.key -c fsync=off"
	run := exec.Command("docker", "run", "-d", "--name", s.container, "-p", "127.0.0.1::5432", //nolint:gosec // G204: a pinned image and our own arguments
		"-e", "POSTGRES_PASSWORD="+s.Password, "-v", dir+":/tls:ro", "--tmpfs", "/var/lib/postgresql",
		"--entrypoint", "sh", image, "-c", setup)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	published, err := exec.Command("docker", "port", s.container, "5432/tcp").Output() //nolint:gosec // G204: our own container name
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	if _, s.Port, err = net.SplitHostPort(strings.TrimSpace(strings.Split(string(published), "\n")[0])); err != nil {
		t.Fatalf("docker port %q: %v", published, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), startup)
	defer cancel()
	// During initdb the entrypoint's temporary server listens on its Unix socket only, so the first
	// TCP connection that works is the final server's.
	for {
		cfg, err := pgxpool.ParseConfig(s.DSN("postgres"))
		if err != nil {
			t.Fatal(err)
		}
		if s.Admin, err = pgxpool.NewWithConfig(ctx, cfg); err == nil {
			if err = s.Admin.Ping(ctx); err == nil {
				t.Cleanup(s.Admin.Close)
				return s
			}
			s.Admin.Close()
		}
		select {
		case <-ctx.Done():
			logs, _ := exec.Command("docker", "logs", "--tail", "60", s.container).CombinedOutput() //nolint:gosec // G204: our own container name
			t.Fatalf("PostgreSQL did not accept a connection within %s: %v\n%s", startup, err, logs)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// DSN is a verify-full URL for database db.
func (s *Server) DSN(db string) string {
	return (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", s.Password), Host: net.JoinHostPort(s.Host, s.Port),
		Path: "/" + db, RawQuery: url.Values{"sslmode": {"verify-full"}, "sslrootcert": {s.CAFile}}.Encode()}).String()
}

// NewDatabase creates an empty database, dropped when the test ends, and returns its name.
func (s *Server) NewDatabase(t *testing.T) string {
	t.Helper()
	name := "t_" + randomHex(t)
	if _, err := s.Admin.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { _, _ = s.Admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)") })
	return name
}

// Exec runs a command in the container (pg_dump, pg_restore) as the postgres user and returns its
// standard output; it fails the test on an error.
func (s *Server) Exec(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"exec", "-i", "-u", "postgres", s.container}, args...)...) //nolint:gosec // G204: our own container and the test's arguments
	cmd.Stdin = strings.NewReader(string(stdin))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", args, err, stderr.String())
	}
	return out
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// CA is a certificate authority made for one test.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	CertPEM []byte
}

// NewCA makes a CA named name, valid from an hour ago for a day.
func NewCA(t *testing.T, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{cert: cert, key: key, CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Issue makes a server certificate for one IP address and returns it with its key, in PEM.
func (ca *CA) Issue(t *testing.T, ip string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}
