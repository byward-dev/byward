package postgres

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/pgtest"
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

const dsnBase = "host=db.example port=5432 user=byward dbname=byward "

// DSNs that are less than verify-full, each for its own reason.
var weakDSNs = []struct {
	name, dsn string
	env       map[string]string
}{
	{"no sslmode is pgx's prefer", dsnBase, nil},
	{"prefer from the environment", dsnBase, map[string]string{"PGSSLMODE": "prefer"}},
	{"disable", dsnBase + "sslmode=disable", nil},
	{"allow", dsnBase + "sslmode=allow", nil},
	{"prefer", dsnBase + "sslmode=prefer", nil},
	{"require", dsnBase + "sslmode=require", nil},
	{"require with a root CA acts as verify-ca", dsnBase + "sslmode=require sslrootcert=" + caPlaceholder, nil},
	{"verify-ca", dsnBase + "sslmode=verify-ca sslrootcert=" + caPlaceholder, nil},
	{"direct negotiation turns prefer into require", dsnBase + "sslmode=prefer sslnegotiation=direct", nil},
	{"a Unix socket gets no TLS", "host=/var/run/postgresql user=byward sslmode=verify-full", nil},
	{"a Unix socket among TCP hosts", "host=db.example,/var/run/postgresql user=byward sslmode=verify-full", nil},
}

// caPlaceholder stands for a CA file a test writes; withCA puts its path in.
const caPlaceholder = "{ca}"

func withCA(dsn, ca string) string { return strings.ReplaceAll(dsn, caPlaceholder, ca) }

// D4 of #227: only verify-full is accepted, judged on what pgx parsed, so neither an environment
// variable nor a missing sslmode (pgx's default is prefer) can weaken it.
func TestOnlyVerifyFullIsAccepted(t *testing.T) {
	ca := writeCA(t)
	for _, tc := range []struct {
		name, dsn string
		env       map[string]string
	}{
		{"verify-full", dsnBase + "sslmode=verify-full", nil},
		{"verify-full with a root CA", dsnBase + "sslmode=verify-full sslrootcert=" + caPlaceholder, nil},
		{"verify-full as a URL", "postgres://byward@db.example/byward?sslmode=verify-full", nil},
		{"sslrootcert=system forces verify-full", dsnBase + "sslmode=require sslrootcert=system", nil},
		{"verify-full on every host", "host=a.example,b.example user=byward sslmode=verify-full", nil},
		{"verify-full from the environment", dsnBase, map[string]string{"PGSSLMODE": "verify-full"}},
		{"direct negotiation with verify-full", dsnBase + "sslmode=verify-full sslnegotiation=direct", nil},
	} {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			if _, err := parseDSN(withCA(tc.dsn, ca), false); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	for _, tc := range weakDSNs {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			if _, err := parseDSN(withCA(tc.dsn, ca), false); err == nil || !strings.Contains(err.Error(), "sslmode=verify-full") {
				t.Fatalf("err = %v, want the verify-full refusal", err)
			}
		})
	}
}

// Development mode lifts the verify-full rule, for every weaker DSN.
func TestDevelopmentModeAcceptsEveryWeakerDSN(t *testing.T) {
	ca := writeCA(t)
	for _, tc := range weakDSNs {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			if _, err := parseDSN(withCA(tc.dsn, ca), true); err != nil {
				t.Fatalf("refused in development mode: %v", err)
			}
		})
	}
}

// Open applies the rule before connecting: a plaintext DSN outside development mode fails at once,
// without a server to connect to.
func TestOpenRefusesPlaintextOutsideDevelopmentMode(t *testing.T) {
	clearPGEnv(t)
	_, err := Open(context.Background(), Options{DSN: "host=127.0.0.1 port=1 user=byward sslmode=disable"})
	if err == nil || !strings.Contains(err.Error(), "sslmode=verify-full") {
		t.Fatalf("err = %v, want the verify-full refusal", err)
	}
}

// A DSN that does not parse is never quoted, whatever the error pgx wraps; a file error keeps its
// path, which helps and holds no secret.
func TestADSNThatDoesNotParseIsNotQuoted(t *testing.T) {
	const secret = "0b6e1f6c-5d0e-4a51-9a59-2f7f6b0f7c3e"
	for _, tc := range []struct{ name, dsn string }{
		{"an invalid port", "postgres://byward:" + secret + "@db.example:port/byward"},
		{"an unescaped slash in the password", "postgres://byward:pass/" + secret + "@db.example:5432/byward"},
		{"an unescaped at sign in the user", "postgres://byward@" + secret + ":x@db.example/byward"},
		{"a bad URL escape", "postgres://byward:" + secret + "@db.example/byward?%zz=1"},
		{"an unterminated quote", "host=db.example password='" + secret},
		{"a bad pool setting", "host=db.example password=" + secret + " pool_max_conns=many"},
		{"a bad connection setting", "host=db.example password=" + secret + " connect_timeout=never"},
		{"an unknown sslmode", "host=db.example password=" + secret + " sslmode=sometimes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearPGEnv(t)
			_, err := parseDSN(tc.dsn, false)
			if err == nil || !strings.Contains(err.Error(), "does not parse") {
				t.Fatalf("err = %v, want the parse refusal", err)
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

// setEnv clears the PG* variables, then sets env.
func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	clearPGEnv(t)
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// writeCA writes a CA certificate for sslrootcert and returns its path.
func writeCA(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pgtest.NewCA(t, "byward test CA").CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
