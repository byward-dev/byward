package memory

import (
	"testing"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/storetest"
)

func TestCollectDropsExpiredSpentRecords(t *testing.T) {
	storetest.CollectDropsExpiredSpent(t, func(*testing.T) store.Store { return New() }, func(_ *testing.T, s store.Store, kind storetest.Spent) int {
		if kind == storetest.SpentLogins {
			return len(s.(*Store).logins)
		}
		return len(s.(*Store).asserts)
	})
}
