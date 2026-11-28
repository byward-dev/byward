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

// A revocation finishes detached from its request, and a request may make two such store calls in a
// row (a refused client's lookup, then its revocation); the shutdown waits for both, so they must
// end inside the grace, while the store is still open (#693).
func TestARevocationOnARequestThatEndsFinishesInsideTheShutdownGrace(t *testing.T) {
	if 2*broker.DetachedTimeout >= ShutdownTimeout {
		t.Fatalf("broker.DetachedTimeout %s, ShutdownTimeout %s: two detached store calls in flight at shutdown would outlive the grace", broker.DetachedTimeout, ShutdownTimeout)
	}
}
