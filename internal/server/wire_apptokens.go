package server

import (
	"time"

	"github.com/byward-dev/byward/internal/apptoken"
	"github.com/byward-dev/byward/internal/denylist"
	"github.com/byward-dev/byward/internal/resource"
)

// appValidator is the app-only path (ADR-0022): the IdP adapter's verifier, the app gate on every
// request, and revoke-user's cut-offs.
func appValidator(parts *authParts, deny *denylist.List, o Observability) (resource.Validator, error) {
	return apptoken.New(apptoken.Config{Verifier: parts.idp.appTokens, Gate: parts.appGate, Deny: deny, IdP: parts.idp.name, Count: o.Metrics.AppToken, Now: time.Now})
}
