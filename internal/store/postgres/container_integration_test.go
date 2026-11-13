//go:build integration

package postgres

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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// postgresImages are the versions the adapter is tested on: the oldest it claims (15) and the
// newest, pinned by digest. Dependabot does not see Go constants: keep each at least 14 days old by
// Docker Hub's last-updated date when updating (ADR-0024 §5). 15.18: 2026-08-05; 18.4: 2026-08-06.
var postgresImages = []struct{ name, image string }{
	{"15", "postgres:15.18@sha256:6eb0add3b77c081df18aa518ce43df58fdcc40f2e6d868a6fd08038dc7acd425"},
	{"18", "postgres:18.4@sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636"},
}

// postgresStartup bounds the image pull, initdb and the first connection.
const postgresStartup = 3 * time.Minute

// server is one PostgreSQL container with TLS on. Its certificate is for 127.0.0.1 only, signed by
// a CA made for the test, so the tests connect with sslmode=verify-full as production must.
type server struct {
	host, port, password string
	caFile               string
	admin                *pgxpool.Pool // the postgres database, for creating and dropping test databases
}

// requirePostgres skips unless BYWARD_POSTGRES=1 (`mise run test:postgres` sets it).
func requirePostgres(t *testing.T) {
	t.Helper()
	if os.Getenv("BYWARD_POSTGRES") != "1" {
		t.Skip("set BYWARD_POSTGRES=1 to run the PostgreSQL tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("BYWARD_POSTGRES=1 but docker is not available: %v", err)
	}
}

// startPostgres runs image with TLS on and returns once it accepts a verify-full connection.
func startPostgres(t *testing.T, image string) *server {
	t.Helper()
	dir := t.TempDir()
	// The container's root reads the files and copies them for the postgres user: world-readable
	// test data, including a key made for this test only.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: test certificates the container reads
		t.Fatal(err)
	}
	ca := newCA(t, "byward test CA")
	certPEM, keyPEM := ca.issue(t, "127.0.0.1")
	for name, data := range map[string][]byte{"ca.pem": ca.certPEM, "server.crt": certPEM, "server.key": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil { //nolint:gosec // G306: read by the container
			t.Fatal(err)
		}
	}
	srv := &server{host: "127.0.0.1", password: randomHex(t), caFile: filepath.Join(dir, "ca.pem")}

	name := "byward-postgres-" + randomHex(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) //nolint:gosec // G204: our own container name
	// PostgreSQL refuses a key readable by others: the entrypoint copies it with mode 0600 for the
	// postgres user before starting the server. Docker picks the host port.
	setup := "install -d -o postgres -m 0700 /run/byward-tls && " +
		"install -o postgres -m 0600 /tls/server.crt /tls/server.key /run/byward-tls/ && " +
		"exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/run/byward-tls/server.crt " +
		"-c ssl_key_file=/run/byward-tls/server.key -c fsync=off"
	run := exec.Command("docker", "run", "-d", "--name", name, "-p", "127.0.0.1::5432", //nolint:gosec // G204: a pinned image and our own arguments
		"-e", "POSTGRES_PASSWORD="+srv.password, "-v", dir+":/tls:ro", "--tmpfs", "/var/lib/postgresql",
		"--entrypoint", "sh", image, "-c", setup)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	published, err := exec.Command("docker", "port", name, "5432/tcp").Output() //nolint:gosec // G204: our own container name
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	_, srv.port, err = net.SplitHostPort(strings.TrimSpace(strings.Split(string(published), "\n")[0]))
	if err != nil {
		t.Fatalf("docker port %q: %v", published, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), postgresStartup)
	defer cancel()
	// During initdb the entrypoint's temporary server listens on its Unix socket only, so the first
	// TCP connection that works is the final server's.
	for {
		cfg, err := pgxpool.ParseConfig(srv.dsn("postgres"))
		if err != nil {
			t.Fatal(err)
		}
		if srv.admin, err = pgxpool.NewWithConfig(ctx, cfg); err == nil {
			if err = srv.admin.Ping(ctx); err == nil {
				t.Cleanup(srv.admin.Close)
				return srv
			}
			srv.admin.Close()
		}
		select {
		case <-ctx.Done():
			logs, _ := exec.Command("docker", "logs", "--tail", "60", name).CombinedOutput() //nolint:gosec // G204: our own container name
			t.Fatalf("PostgreSQL did not accept a connection within %s: %v\n%s", postgresStartup, err, logs)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// dsn is a verify-full URL for database db.
func (s *server) dsn(db string) string {
	return (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", s.password), Host: net.JoinHostPort(s.host, s.port),
		Path: "/" + db, RawQuery: url.Values{"sslmode": {"verify-full"}, "sslrootcert": {s.caFile}}.Encode()}).String()
}

// database creates an empty database, dropped when the test ends, and returns its name.
func (s *server) database(t *testing.T) string {
	t.Helper()
	name := "t_" + randomHex(t)
	if _, err := s.admin.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { _, _ = s.admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)") })
	return name
}

// open opens a store on a new database.
func (s *server) open(t *testing.T) (*Store, string) {
	t.Helper()
	db := s.database(t)
	return s.openOn(t, db), db
}

// openOn opens a store on database db, closed when the test ends.
func (s *server) openOn(t *testing.T, db string) *Store {
	t.Helper()
	st, err := Open(bounded(t), Options{DSN: s.dsn(db)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// conn is a plain connection to database db, for setting up and inspecting what the store cannot.
func (s *server) conn(t *testing.T, db string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(bounded(t), s.dsn(db))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// bounded is a context that ends with the test, or after a minute.
func bounded(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newCA(t *testing.T, name string) *testCA {
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
	return &testCA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue makes a server certificate for one IP address and returns it with its key, in PEM.
func (ca *testCA) issue(t *testing.T, ip string) (certPEM, keyPEM []byte) {
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

// waitFor polls query on c until it returns true, or fails the test after 10 s.
func waitFor(t *testing.T, c *pgx.Conn, what, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var ok bool
		if err := c.QueryRow(context.Background(), query, args...).Scan(&ok); err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
