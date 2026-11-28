package server

import (
	"testing"

	"github.com/byward-dev/byward/internal/broker"
)

// A callback that has spent its login finishes on its own, detached from its request; the shutdown
// waits for it, so it must end inside the grace, while the store is still open (ADR-0018 §9, #672).
func TestACallbackPastItsLoginFinishesInsideTheShutdownGrace(t *testing.T) {
	if broker.CallbackTimeout >= ShutdownTimeout {
		t.Fatalf("broker.CallbackTimeout %s, ShutdownTimeout %s: a callback in flight at shutdown would outlive the grace", broker.CallbackTimeout, ShutdownTimeout)
	}
}
