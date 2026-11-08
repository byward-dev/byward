package server

// wireOBO is On-Behalf-Of for the HTTP upstream (ADR-0017); off without downstream scopes.
func wireOBO(w *wiring, a *auth) error {
	if len(w.cfg.OBOScopes) == 0 {
		return nil
	}
	// config refuses On-Behalf-Of with any IdP but Entra, so ip.entra is set.
	ip := w.parts.idp
	a.downstream = newDownstreamTokens(w.cfg.OBOScopes, w.cfg.OBOHeader, ip.entra, ip.name, w.broker.IdPAccessToken, w.log, w.o)
	w.log.Info("On-Behalf-Of", "reason", "downstream API "+a.downstream.resource+"; access tokens are capped at the stored IdP token's expiry",
		"setting", "BYWARD_OBO_HEADER", "value", w.cfg.OBOHeader)
	return nil
}
