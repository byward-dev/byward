package memory

import (
	"testing"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/storetest"
)

func TestCollectDropsExpiredSpentRecords(t *testing.T) {
	storetest.CollectDropsExpiredSpent(t, func(*testing.T) (store.Store, func(storetest.Spent) int) {
		s := New()
		return s, func(kind storetest.Spent) int {
			if kind == storetest.SpentLogins {
				return len(s.logins)
			}
			return len(s.asserts)
		}
	})
}
