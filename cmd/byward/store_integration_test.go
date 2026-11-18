//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/store/postgres"
	"github.com/byward-dev/byward/internal/testutil/pgtest"
)

// L152 on PostgreSQL: an operator command on a database without byward's schema exits 2 naming the
// setting; on the store it exits 0 and its success line names the database, never the DSN.
func TestIntegrationOperatorCommandsOnPostgreSQLExit2WithoutTheSchemaAndNameTheDatabase(t *testing.T) {
	pgtest.Require(t)
	srv := pgtest.Start(t, pgtest.Images[len(pgtest.Images)-1].Image)
	env := func(t *testing.T, db string) []string {
		file := filepath.Join(t.TempDir(), "dsn")
		if err := os.WriteFile(file, []byte(srv.DSN(db)), 0o600); err != nil {
			t.Fatal(err)
		}
		var kept []string
		for _, kv := range authEnv(t) {
			if !strings.HasPrefix(kv, "BYWARD_STORE_DIR=") {
				kept = append(kept, kv)
			}
		}
		return append(kept, "BYWARD_STORE_POSTGRES_DSN_FILE="+file, "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp")
	}
	const user = "00000000-0000-0000-0000-000000000001:11111111-1111-1111-1111-11111111111a"
	const wayOut = "; run the command with the proxy's settings (see docs/how-to/postgres.md)\n"
	for _, c := range []struct {
		name, command string
		success       string // the whole success line; {varies} is the database's description
		args          []string
	}{
		{"revoke-user", "revoke-user", "revoked user " + user + " in BYWARD_STORE_POSTGRES_DSN_FILE ({varies})" + revoked, []string{"revoke-user", user}},
		{"revoke-all", "revoke-all", "revoked every user in BYWARD_STORE_POSTGRES_DSN_FILE ({varies})" + revoked, []string{"revoke-all", "--yes"}},
		{"new-epoch", "store new-epoch", "started store epoch 2 in BYWARD_STORE_POSTGRES_DSN_FILE ({varies}): refresh tokens from before it stop working, and their users sign in again\n", []string{"store", "new-epoch", "--yes"}},
	} {
		t.Run(c.name+" without the schema", func(t *testing.T) {
			db := srv.NewDatabase(t)
			code, stdout, stderr := runWith(c.args, env(t, db)...)
			want := "byward: " + c.command + ": BYWARD_STORE_POSTGRES_DSN_FILE: no byward store there: the database ({varies}) holds no byward schema" + wayOut
			if code != exitConfig || stdout != "" || !outputMatches(stderr, want) || !strings.Contains(stderr, "dbname="+db) || strings.Contains(stderr, srv.Password) {
				t.Fatalf("code %d (want %d), stdout %q (want none)\nstderr %q\nwant   %q naming dbname=%s, never the password", code, exitConfig, stdout, stderr, want, db)
			}
		})
		t.Run(c.name+" on the store", func(t *testing.T) {
			db := srv.NewDatabase(t)
			st, err := postgres.Open(context.Background(), postgres.Options{DSN: srv.DSN(db)})
			if err != nil {
				t.Fatal(err)
			}
			_ = st.Close()
			code, stdout, stderr := runWith(c.args, env(t, db)...)
			if code != exitOK || !outputMatches(stdout, c.success) || !strings.Contains(stdout, "dbname="+db) || strings.Contains(stdout, srv.Password) {
				t.Fatalf("code %d (want %d)\nstdout %q\nwant   %q naming dbname=%s, never the password\nstderr %q", code, exitOK, stdout, c.success, db, stderr)
			}
		})
	}
}
