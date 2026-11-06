package sqlite

import (
	"path/filepath"
	"testing"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/storetest"
)

// openTemp opens a store in a fresh directory, with the counter file in another one (as it would
// sit next to the keys).
func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(bounded(t), Options{Dir: t.TempDir(), CounterFile: filepath.Join(t.TempDir(), "store-writes")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return openTemp(t) })
}
