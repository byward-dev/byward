package memory_test

import (
	"testing"

	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/store/memory"
	"github.com/corker/mcp-authproxy/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return memory.New() })
}
