package server

import (
	"strings"
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

// wireAppTokens is the validator for app-only tokens (ADR-0022), nil while they are off so a JWT
// reaches no validator.
func wireAppTokens(w *wiring, deny *denylist.List) (resource.Validator, error) {
	if w.parts.appGate == nil {
		return nil, nil
	}
	app, err := appValidator(w.parts, deny, w.o)
	if err != nil {
		return nil, err
	}
	w.log.Info("app-only tokens", "reason", "accepting Entra app-only tokens with app roles "+strings.Join(w.cfg.AppRoles, ", ")+" (ADR-0022)")
	return app, nil
}
