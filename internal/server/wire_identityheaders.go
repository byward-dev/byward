package server

// wireIdentityHeaders warns, at every start, that the plain identity headers are on (ADR-0016 §5);
// they ride on the assertion, so a stdio upstream gets none.
func wireIdentityHeaders(w *wiring, a *auth) error {
	if w.cfg.IdentityHeaders && a.minter != nil {
		w.log.Warn("plain identity headers are on", "setting", "BYWARD_IDENTITY_HEADERS",
			"reason", "the upstream gets the user in X-Byward-* headers as well as the assertion; that is safe only when it is reachable through this proxy alone (docs/how-to/plain-identity-headers.md)")
	}
	return nil
}
