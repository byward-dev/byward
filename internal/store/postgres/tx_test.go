package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/byward-dev/byward/internal/store"
)

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

// A write is attempted until it succeeds, fails for good, or has lost maxAttempts races; a store
// error ends it at once and comes back as it is.
func TestAWriteIsRetriedOnlyWhileItLosesRaces(t *testing.T) {
	lost := &pgconn.PgError{Code: "40001"}
	for _, tc := range []struct {
		name      string
		results   []error // attempt n returns results[n-1], and the last one from then on
		wantCalls int
		check     func(error) bool
	}{
		{"a race lost once, then success", []error{lost, nil}, 2, func(err error) bool { return err == nil }},
		{"a store error is final", []error{store.ErrExists}, 1, func(err error) bool { return errors.Is(err, store.ErrExists) }},
		{"races lost every time", []error{lost}, maxAttempts, func(err error) bool {
			var pg *pgconn.PgError
			return errors.As(err, &pg) && strings.Contains(err.Error(), fmt.Sprintf("still conflicting after %d attempts", maxAttempts))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := retryLostRaces(context.Background(), func() error {
				calls++
				return tc.results[min(calls, len(tc.results))-1]
			})
			if calls != tc.wantCalls || !tc.check(err) {
				t.Fatalf("%d attempts, err = %v; want %d attempts and the expected error", calls, err, tc.wantCalls)
			}
		})
	}
}

// A context that ends during the pause after a lost race stops the retries.
func TestACancelledWriteStopsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := retryLostRaces(ctx, func() error {
		calls++
		cancel()
		return &pgconn.PgError{Code: "40001"}
	})
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("%d attempts, err = %v; want 1 attempt and context.Canceled", calls, err)
	}
}
