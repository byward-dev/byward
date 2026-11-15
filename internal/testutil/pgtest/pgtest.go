// Package pgtest runs PostgreSQL for tests: a container per pinned image, with TLS on and a
// certificate from a CA made for the test, so tests connect with sslmode=verify-full as production
// must (#227). It needs Docker and runs only when BYWARD_POSTGRES=1 (`mise run test:postgres`).
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/byward-dev/byward/internal/testutil/testcert"
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
func Require(t testing.TB) {
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
func Start(t testing.TB, image string) *Server {
	t.Helper()
	dir := t.TempDir()
	// The container's root reads the files and copies them for the postgres user: world-readable
	// test data, including a key made for this test only.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: test certificates the container reads
		t.Fatal(err)
	}
	b := testcert.Issue(t, testcert.Options{Hosts: []string{"127.0.0.1"}, Leaf: testcert.Valid(time.Now(), 1)})
	for name, data := range map[string][]byte{"ca.pem": b.RootPEM, "server.crt": b.Cert, "server.key": b.Key} {
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
func (s *Server) NewDatabase(t testing.TB) string {
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
func (s *Server) Exec(t testing.TB, stdin []byte, args ...string) []byte {
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

func randomHex(t testing.TB) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
