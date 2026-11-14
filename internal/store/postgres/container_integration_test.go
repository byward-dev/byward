//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/pgtest"
	"github.com/jackc/pgx/v5"
)

// server is a pgtest container, with the adapter's own helpers.
type server struct{ *pgtest.Server }

var postgresImages = pgtest.Images

func requirePostgres(t *testing.T) { pgtest.Require(t) }

func startPostgres(t *testing.T, image string) *server { return &server{pgtest.Start(t, image)} }

func (s *server) dsn(db string) string { return s.DSN(db) }

func (s *server) newDatabase(t *testing.T) string { return s.NewDatabase(t) }

// open opens a store on a new database.
func (s *server) open(t *testing.T) (*Store, string) {
	t.Helper()
	db := s.newDatabase(t)
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
