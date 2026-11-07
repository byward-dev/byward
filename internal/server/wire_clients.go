package server

import (
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/registration"
)

// newCIMDRegistry is registration.NewCIMDRegistry; tests replace it to see the wired host lists.
var newCIMDRegistry = registration.NewCIMDRegistry

// wireCIMD is Client ID Metadata Documents (ADR-0008 §4): clients identified by a metadata URL,
// fetched through the SSRF guard.
func wireCIMD(w *wiring) (registration.Registry, broker.Registrar) {
	if !w.cfg.CIMD {
		return nil, nil
	}
	return newCIMDRegistry(registration.CIMDConfig{Fetch: w.guard, KeysClient: w.guard.HTTPClient(),
		TrustedHosts: w.cfg.CIMDTrustedHosts, AllowedHosts: w.cfg.CIMDAllowedHosts, Deny: w.parts.clientDeny, JTI: w.parts.jti, Now: time.Now, Observe: w.o.Metrics.CIMDFetch}), nil
}

// wireDCR is Dynamic Client Registration (ADR-0008 §2-3): clients that register at /register.
func wireDCR(w *wiring) (registration.Registry, broker.Registrar) {
	if !w.cfg.DCR {
		return nil, nil
	}
	dcr := registration.NewDCRRegistry(registration.DCRConfig{Store: w.store, KeysClient: w.guard.HTTPClient(), JTI: w.parts.jti, Now: time.Now,
		Scopes: []string{w.cfg.Scope, "offline_access"}, Deny: w.parts.clientDeny})
	return dcr, dcr
}
