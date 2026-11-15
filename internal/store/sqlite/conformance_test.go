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
	return open(t, t.TempDir(), filepath.Join(t.TempDir(), "store-writes"))
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return openTemp(t) })
}
