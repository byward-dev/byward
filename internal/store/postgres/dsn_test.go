package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/byward-dev/byward/internal/store"
)

// clearPGEnv unsets the PG* variables pgx reads, so the developer's environment cannot change a
// case; a case sets what it needs afterwards.
func clearPGEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "PG") {
			t.Setenv(name, "")
			_ = os.Unsetenv(name)
		}
	}
	t.Setenv("PGPASSFILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("PGSERVICEFILE", filepath.Join(t.TempDir(), "none"))
}

// D4 of #227: only verify-full is accepted, judged on what pgx parsed, so neither an environment
// variable nor a missing sslmode (pgx's default is prefer) can weaken it.
func TestOnlyVerifyFullIsAccepted(t *testing.T) {
	ca := writeCA(t)
	const base = "host=db.example port=5432 user=byward dbname=byward "
	for _, tc := range []struct {
		name string
		dsn  string
		env  map[string]string
		ok   bool
	}{
		{"verify-full", base + "sslmode=verify-full", nil, true},
		{"verify-full with a root CA", base + "sslmode=verify-full sslrootcert=" + ca, nil, true},
		{"verify-full as a URL", "postgres://byward@db.example/byward?sslmode=verify-full", nil, true},
		{"sslrootcert=system forces verify-full", base + "sslmode=require sslrootcert=system", nil, true},
		{"verify-full on every host", "host=a.example,b.example user=byward sslmode=verify-full", nil, true},
		{"verify-full from the environment", base, map[string]string{"PGSSLMODE": "verify-full"}, true},
		{"direct negotiation with verify-full", base + "sslmode=verify-full sslnegotiation=direct", nil, true},

		{"no sslmode is pgx's prefer", base, nil, false},
		{"prefer from the environment", base, map[string]string{"PGSSLMODE": "prefer"}, false},
		{"disable", base + "sslmode=disable", nil, false},
		{"allow", base + "sslmode=allow", nil, false},
		{"prefer", base + "sslmode=prefer", nil, false},
		{"require", base + "sslmode=require", nil, false},
		{"require with a root CA acts as verify-ca", base + "sslmode=require sslrootcert=" + ca, nil, false},
		{"verify-ca", base + "sslmode=verify-ca sslrootcert=" + ca, nil, false},
		{"direct negotiation turns prefer into require", base + "sslmode=prefer sslnegotiation=direct", nil, false},
		{"a Unix socket gets no TLS", "host=/var/run/postgresql user=byward sslmode=verify-full", nil, false},
		{"a Unix socket among TCP hosts", "host=db.example,/var/run/postgresql user=byward sslmode=verify-full", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearPGEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := parseDSN(tc.dsn, false)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "sslmode=verify-full")) {
				t.Fatalf("err = %v, want the verify-full refusal", err)
			}
		})
	}
}

// Development mode accepts plaintext.
func TestDevelopmentModeAcceptsPlaintext(t *testing.T) {
	clearPGEnv(t)
	cfg, err := parseDSN("host=127.0.0.1 user=byward sslmode=disable", true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.TLSConfig != nil {
		t.Fatalf("TLS config %+v, want plaintext", cfg.ConnConfig.TLSConfig)
	}
}

// The check reads every TLS config, not only the first: a later host with a weaker one fails it.
func TestAWeakFallbackIsRefused(t *testing.T) {
	clearPGEnv(t)
	cfg, err := parseDSN("host=a.example,b.example user=byward sslmode=verify-full", false)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.ConnConfig.Config
	c.Fallbacks = []*pgconn.FallbackConfig{{Host: "b.example", Port: 5432, TLSConfig: nil}}
	if err := requireVerifyFull(&c); err == nil {
		t.Fatal("a plaintext fallback passed")
	}
	insecure := c.TLSConfig.Clone()
	insecure.InsecureSkipVerify = true
	c.Fallbacks = []*pgconn.FallbackConfig{{Host: "b.example", Port: 5432, TLSConfig: insecure}}
	if err := requireVerifyFull(&c); err == nil {
		t.Fatal("a fallback without verification passed")
	}
}

// A DSN that does not parse is never quoted, whatever the error pgx wraps; a file error keeps its
// path, which helps and holds no secret.
func TestADSNThatDoesNotParseIsNotQuoted(t *testing.T) {
	const secret = "0b6e1f6c-5d0e-4a51-9a59-2f7f6b0f7c3e"
	for _, dsn := range []string{
		"postgres://byward:" + secret + "@db.example:port/byward",       // invalid port
		"postgres://byward:" + secret + ":x@db.example/byward",          // a mislaid password lands in the port
		"postgres://byward:" + secret + "@db.example/byward?%zz=1",      // bad URL escape
		"host=db.example password='" + secret,                           // unterminated quote
		"host=db.example password=" + secret + " pool_max_conns=many",   // a pool setting
		"host=db.example password=" + secret + " connect_timeout=never", // a connection setting
		"host=db.example password=" + secret + " sslmode=sometimes",     // an unknown sslmode
	} {
		t.Run(dsn[:20], func(t *testing.T) {
			clearPGEnv(t)
			_, err := parseDSN(dsn, false)
			if err == nil {
				t.Fatal("parsed")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "db.example") {
				t.Fatalf("the error quotes the DSN: %v", err)
			}
		})
	}
	t.Run("a missing CA file is named", func(t *testing.T) {
		clearPGEnv(t)
		missing := filepath.Join(t.TempDir(), "no-ca.pem")
		_, err := parseDSN("host=db.example password="+secret+" sslmode=verify-full sslrootcert="+missing, false)
		if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), missing) || strings.Contains(err.Error(), secret) {
			t.Fatalf("err = %v, want the missing file named and no password", err)
		}
	})
}

// Only a lost race is retried: a serialization failure, a deadlock or a concurrent insert of the
// same key, wrapped or not; the store's own errors and other database errors are final.
func TestOnlyALostRaceIsRetried(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&pgconn.PgError{Code: "40001"}, true},
		{&pgconn.PgError{Code: "40P01"}, true},
		{&pgconn.PgError{Code: "23505"}, true},
		{fmt.Errorf("postgres store: commit: %w", &pgconn.PgError{Code: "40001"}), true},
		{&pgconn.PgError{Code: "23503"}, false}, // foreign key
		{&pgconn.PgError{Code: "57014"}, false}, // query canceled
		{store.ErrExists, false},
		{errors.New("40001"), false},
		{nil, false},
	} {
		if got := retryable(tc.err); got != tc.want {
			t.Errorf("retryable(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// The store's errors come back as they are; database errors name the adapter and still unwrap.
func TestWrapKeepsTheStoresErrors(t *testing.T) {
	for _, e := range []error{store.ErrNotFound, store.ErrConsumed, store.ErrExists, store.ErrInvalid, store.ErrRevoked, store.ErrReused, store.ErrFull} {
		if got := wrap(e); got != e { //nolint:errorlint // identity is the point
			t.Errorf("wrap(%v) = %v", e, got)
		}
	}
	pg := &pgconn.PgError{Code: "23503"}
	if got := wrap(pg); !errors.Is(got, pg) || !strings.HasPrefix(got.Error(), "postgres store: ") {
		t.Errorf("wrap(pg) = %v", got)
	}
}

func TestEverySchemaVersionHasAFixture(t *testing.T) {
	for v := 1; v <= schemaVersion(); v++ {
		if _, err := os.Stat(fixturePath(v)); err != nil {
			t.Errorf("schema v%d has no fixture %s: add one when releasing a schema version", v, fixturePath(v))
		}
	}
}

func fixturePath(v int) string { return filepath.Join("testdata", "schema", fmt.Sprintf("v%d.sql", v)) }

// writeCA writes a self-signed CA certificate for sslrootcert and returns its path.
func writeCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "byward test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
