package server

import (
	"context"
	"errors"

	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/token"
)

// readiness is what /readyz checks in authenticated mode: a signing key and the store. Never the
// IdP (ADR-0021 §10).
func readiness(ring *token.KeyRing, st pinger) []health.Check {
	checks := []health.Check{{Name: "keys", Ready: func(context.Context) error {
		if ring.SigningKeyID() == "" {
			return errors.New("no signing key")
		}
		return nil
	}}}
	return append(checks, health.Check{Name: "store", Ready: st.Ping})
}

// pinger is a store that can say whether it is reachable, for readiness.
type pinger interface{ Ping(context.Context) error }
