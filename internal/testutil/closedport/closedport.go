// Package closedport gives a test a local address nothing listens on, so every dial to it fails at
// once, with no DNS lookup and nothing leaving the machine.
package closedport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Addr is a loopback host:port that was listening a moment ago and no longer is.
func Addr(t testing.TB) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	addr := s.Listener.Addr().String()
	s.Close()
	return addr
}
