// Package health serves the probes on the internal listener (ADR-0021 §10): `/livez` is the
// process, `/readyz` is config, keys and store. The IdP is never part of readiness: MCP requests are
// validated locally (ADR-0014), so an IdP outage must not take every replica out of service.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Check is one readiness condition. Ready returns nil when the condition holds.
type Check struct {
	Name  string
	Ready func(context.Context) error
}

// Health holds the readiness checks and the draining flag.
type Health struct {
	log      *slog.Logger
	checks   []Check
	draining atomic.Bool
}

// checkTimeout bounds one readiness check, so a hung store cannot hang the probe.
const checkTimeout = 2 * time.Second

// New returns probes over checks; failures are logged at warning level (names and errors only).
func New(log *slog.Logger, checks ...Check) *Health {
	return &Health{log: log, checks: checks}
}

// Drain makes `/readyz` fail from now on, so load balancers stop sending traffic before shutdown.
func (h *Health) Drain() { h.draining.Store(true) }

// Register adds `/livez` and `/readyz` to mux.
func (h *Health) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", h.ready)
}

func (h *Health) ready(w http.ResponseWriter, r *http.Request) {
	results := map[string]string{}
	status := http.StatusOK
	if h.draining.Load() {
		results["draining"] = "fail"
		status = http.StatusServiceUnavailable
	}
	for _, c := range h.checks {
		ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
		err := c.Ready(ctx)
		cancel()
		if err != nil {
			results[c.Name] = "fail"
			status = http.StatusServiceUnavailable
			h.log.WarnContext(r.Context(), "readiness check failed", "reason", c.Name, "error", err)
			continue
		}
		results[c.Name] = "ok"
	}
	s := "ok"
	if status != http.StatusOK {
		s = "unavailable"
	}
	write(w, status, map[string]any{"status": s, "checks": results})
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
