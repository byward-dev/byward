package memory_test

import (
	"testing"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return memory.New() })
}
