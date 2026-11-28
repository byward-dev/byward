package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/shutdown"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/token"
)

// On the wired SQLite store, a revocation a client asks for at /revoke still ends its grant when
// the request ends once its form is read, as its client going away or the proxy's shutdown: the
// grant is gone from the store, so every replica refuses it and its refresh tokens stop (#693).
// SQLite takes no connection for an ended context, so a revocation left on the request's context
// would fail and leave the grant live.
func TestARevocationOnARequestThatEndedStillEndsTheGrantInTheSQLiteStore(t *testing.T) {
	endings := map[string]func() (context.Context, func()){
		"client gone": func() (context.Context, func()) { return context.WithCancel(context.Background()) },
		"shutdown":    func() (context.Context, func()) { return shutdown.WithCancel(context.Background()) },
	}
	for name, start := range endings {
		t.Run(name, func(t *testing.T) {
			_, cfg := storeEnv(t)
			now := time.Now()
			rt, hash := token.NewRefreshToken()
			withStore(t, cfg, func(st *sqlite.Store) {
				if _, err := st.CreateGrant(context.Background(), grantFor("g", now)); err != nil {
					t.Fatal(err)
				}
				if err := st.PutRefreshToken(context.Background(), store.RefreshToken{Hash: hash, GrantID: "g", ClientID: "test-app",
					CreatedAt: now, IdleExpiresAt: now.Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
			})
			a, err := buildAuth(cfg, discard, Observability{})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			a.register(mux)
			ctx, end := start()
			end()
			r := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/revoke",
				strings.NewReader(url.Values{"token": {rt}, "client_id": {"test-app"}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			mux.ServeHTTP(httptest.NewRecorder(), r.WithContext(ctx))
			stop(t, a)
			withStore(t, cfg, func(st *sqlite.Store) {
				if _, err := st.Grant(context.Background(), "g"); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("the grant after a revocation whose request ended: err = %v, want it gone from the store", err)
				}
			})
		})
	}
}
