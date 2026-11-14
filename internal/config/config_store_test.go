package config

import (
	"slices"
	"strings"
	"testing"
)

const dsnFile = "/run/secrets/postgres-dsn"

// pgDSN is a connection string with a password, as an operator writes it.
const pgDSN = "postgres://byward:4f6b0c3a-9d2e-4e57-8a51-0c1d2e3f4a5b@db.example:5432/byward?sslmode=verify-full"

// loadDSN loads base plus env, with dsnFile holding pgDSN.
func loadDSN(t *testing.T, args []string, env ...string) (*Config, error) {
	t.Helper()
	files := func(p string) ([]byte, error) {
		if p == dsnFile {
			return []byte(pgDSN + "\n"), nil
		}
		return baseFiles(p)
	}
	c, _, err := Load(args, append(append([]string{}, base...), env...), files)
	return c, err
}

// The SQLite store is the default; the DSN file selects PostgreSQL, without its trailing newline,
// and no setting shows the DSN.
func TestTheDSNFileSelectsPostgreSQLAndIsNeverShown(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.StorePostgresDSN != "" {
		t.Fatalf("PostgreSQL selected without a DSN: %q", c.StorePostgresDSN)
	}
	c, err = loadDSN(t, nil, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
	if err != nil {
		t.Fatal(err)
	}
	if c.StorePostgresDSN != pgDSN {
		t.Fatalf("DSN %q, want the file's content without its newline", c.StorePostgresDSN)
	}
	for _, v := range c.Values.Effective() {
		if strings.Contains(v.Display(), "4f6b0c3a") || strings.Contains(v.Display(), "db.example") {
			t.Fatalf("%s shows the DSN: %s", v.Setting.Env(), v.Display())
		}
	}
}

// One store only, with no SQLite setting it would ignore, and PostgreSQL never with a stdio
// upstream; each refusal names the settings.
func TestThePostgreSQLStoreRefusesSQLiteSettingsOrAStdioUpstream(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"with a state directory", nil, []string{"BYWARD_STORE_DIR=/var/lib/byward/state"}, "BYWARD_STORE_DIR"},
		{"with a counter file", nil, []string{"BYWARD_STORE_COUNTER_FILE=/var/lib/byward/store-writes"}, "BYWARD_STORE_COUNTER_FILE"},
		{"with a stdio upstream", []string{"--", "node", "server.js"}, []string{"BYWARD_UPSTREAM_URL="}, "stdio upstream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadDSN(t, tc.args, append([]string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + dsnFile}, tc.env...)...)
			if err == nil || !strings.Contains(err.Error(), "BYWARD_STORE_POSTGRES_DSN_FILE") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal naming BYWARD_STORE_POSTGRES_DSN_FILE and %s", err, tc.want)
			}
		})
	}
}

// Development mode lists the PostgreSQL relaxation only when PostgreSQL is selected.
func TestDevelopmentModeListsThePlaintextPostgreSQLRelaxationOnlyForPostgreSQL(t *testing.T) {
	const relaxed = "the PostgreSQL store accepts a connection without verify-full TLS"
	c, err := loadDSN(t, []string{"--dev"}, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.Relaxations, relaxed) {
		t.Fatalf("relaxations %q, want %q", c.Relaxations, relaxed)
	}
	if c, err = load(t, []string{"--dev"}); err != nil || slices.Contains(c.Relaxations, relaxed) {
		t.Fatalf("SQLite in development mode: relaxations %q, %v", c.Relaxations, err)
	}
	// Without --dev nothing is relaxed, so a production start never logs it (#355).
	if c, err = loadDSN(t, nil, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile); err != nil || slices.Contains(c.Relaxations, relaxed) {
		t.Fatalf("PostgreSQL outside development mode: relaxations %q, %v", c.Relaxations, err)
	}
}
