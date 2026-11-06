package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/denylist"
	"github.com/corker/mcp-authproxy/internal/health"
	"github.com/corker/mcp-authproxy/internal/token"
)

// The deny list refuses every token once it is older than denylist.MaxStaleness, so the wiring
// must sync it before serving and keep it fresh in the background (ADR-0006 §3).
func TestRevocationListStaysFreshWhileTheServerRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp")
		cfg, _, err := config.Load(nil, env, os.ReadFile)
		if err != nil {
			t.Fatal(err)
		}
		a, err := buildAuth(cfg, discard, Observability{})
		if err != nil {
			t.Fatal(err)
		}
		access := sealAccess(t, cfg, env)
		if _, err := a.validator.Validate(context.Background(), access); err != nil {
			t.Fatalf("right after startup: %v (the list must be synced before serving)", err)
		}

		ctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); a.background(ctx) }()
		time.Sleep(3 * denylist.MaxStaleness) // fake time inside the bubble
		synctest.Wait()
		if _, err := a.validator.Validate(context.Background(), access); err != nil {
			t.Fatalf("after %v of serving: %v (the background sync is not running)", 3*denylist.MaxStaleness, err)
		}
		stop()
		<-done // the background work ends with its context
	})
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func sealAccess(t *testing.T, cfg *config.Config, env []string) string {
	t.Helper()
	var keysDir string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "MCP_AUTHPROXY_KEYS_DIR="); ok {
			keysDir = v
		}
	}
	ring, err := token.LoadKeyRing(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.NewSealer(ring, cfg.PublicURL.String())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := s.Seal(token.Access, token.Claims{GrantID: "g", Subject: "tid:oid", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Run is what starts the background work in production: it must start it once the listener is up
// and stop it when Run returns, with or without the internal listener (on by default).
func TestRunStartsTheBackgroundWorkAndStopsItWithRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		internal *http.Server
	}{
		{"public listener only", nil},
		{"with the internal listener", &http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			s := &Servers{Public: &http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second},
				Internal: tc.internal, Health: health.New(discard),
				background: func(ctx context.Context) {
					close(started)
					<-ctx.Done()
					close(stopped)
				}}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Run(ctx, s, discard) }()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not start the background work")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("Run: %v", err)
			}
			select {
			case <-stopped:
			default:
				t.Fatal("Run returned while the background work was still running")
			}
		})
	}
}

func TestRunWithAFailedListenStartsNoBackgroundWork(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	ran := false
	s := &Servers{Public: &http.Server{Addr: busy.Addr().String(), ReadHeaderTimeout: time.Second}, Health: health.New(discard),
		background: func(context.Context) { ran = true }}
	if err := Run(context.Background(), s, discard); err == nil {
		t.Fatal("Run succeeded on a busy address")
	}
	if ran {
		t.Fatal("background work started although the server never listened")
	}
}

// When serving ends by itself (here: the server is closed) while Run's context is still live, the
// background work must stop with Run too.
func TestBackgroundWorkStopsWhenServingEndsOnItsOwn(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	s := &Servers{Public: &http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}, Health: health.New(discard),
		background: func(ctx context.Context) {
			close(started)
			<-ctx.Done()
			close(stopped)
		}}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), s, discard) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not start the background work")
	}
	_ = s.Public.Close()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Run = %v, want http.ErrServerClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the server closed")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Run returned while the background work was still running")
	}
}
