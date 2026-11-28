package lifecycle

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byward-dev/byward/internal/shutdown"
)

// NewShutdownServer is an unstarted server for h whose requests shutDown ends as the proxy's
// shutdown does: through shutdown.WithCancel, with h wrapped in shutdown.CutsBodyReads, as the
// server's serve and hardened do (internal/server/run.go). The caller starts the server and closes
// it. Its requests are under t.Context(), which ends before any cleanup runs, so a test that fails
// before shutDown still ends its requests (as a client gone) before the server's Close waits for
// them.
func NewShutdownServer(t testing.TB, h http.Handler) (srv *httptest.Server, shutDown func()) {
	t.Helper()
	srv = httptest.NewUnstartedServer(shutdown.CutsBodyReads(h))
	base, shutDown := shutdown.WithCancel(t.Context())
	t.Cleanup(shutDown)
	srv.Config.BaseContext = func(net.Listener) context.Context { return base }
	return srv, shutDown
}
