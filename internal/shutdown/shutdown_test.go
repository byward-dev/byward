package shutdown

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A request whose context ended is answered by how it ended, and the caller then logs nothing as a
// failure: the proxy shutting down (cause http.ErrServerClosed, however wrapped) leaves the MCP
// client there, which gets 503 on a connection that closes; the client going away (the plain
// context.Canceled) records 499, never sent. A request still live, or one ended for another cause
// such as a deadline, is left to the caller (#527, #529).
func TestAnEndedRequestIsAnsweredOnlyWhenTheProxyShutsDownOrItsMCPClientWentAway(t *testing.T) {
	live := context.Background()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, shutDown := WithCancel(context.Background())
	shutDown()
	wrapped, stopWrapped := context.WithCancelCause(context.Background())
	stopWrapped(fmt.Errorf("serve: %w", http.ErrServerClosed))
	late, stopLate := context.WithTimeout(context.Background(), 0)
	defer stopLate()
	other, stopOther := context.WithCancelCause(context.Background())
	stopOther(errors.New("some other cause"))
	for _, c := range []struct {
		name         string
		ctx          context.Context
		answered     bool
		shuttingDown bool
		status       int
		body         string
		connection   string
	}{
		{"still live", live, false, false, http.StatusOK, "", ""},
		{"the MCP client went away", gone, true, false, 499, "", ""},
		{"the proxy shuts down", stopped, true, true, http.StatusServiceUnavailable, "the proxy is shutting down\n", "close"},
		{"the proxy shuts down, its cause wrapped", wrapped, true, true, http.StatusServiceUnavailable, "the proxy is shutting down\n", "close"},
		{"its deadline passed", late, false, false, http.StatusOK, "", ""},
		{"ended for another cause", other, false, false, http.StatusOK, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ShuttingDown(c.ctx); got != c.shuttingDown {
				t.Fatalf("ShuttingDown = %v; want %v", got, c.shuttingDown)
			}
			w := httptest.NewRecorder()
			got := AnswerIfEnded(w, httptest.NewRequestWithContext(c.ctx, http.MethodPost, "/mcp", nil))
			if got != c.answered || w.Code != c.status || w.Body.String() != c.body || w.Header().Get("Connection") != c.connection {
				t.Fatalf("AnswerIfEnded = %v, answer %d %q, Connection %q; want %v, %d %q, %q",
					got, w.Code, w.Body, w.Header().Get("Connection"), c.answered, c.status, c.body, c.connection)
			}
		})
	}
}
