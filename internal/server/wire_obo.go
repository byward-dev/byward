package server

// wireOBO is On-Behalf-Of (ADR-0017): a header for an HTTP upstream, the token socket for a stdio
// one; off without downstream scopes.
func wireOBO(w *wiring, a *auth) error {
	if len(w.cfg.OBOScopes) == 0 {
		return nil
	}
	// config refuses On-Behalf-Of with any IdP but Entra, so ip.entra is set.
	ip := w.parts.idp
	a.downstream = newDownstreamTokens(w.cfg.OBOScopes, w.cfg.OBOHeader, ip.entra, ip.name, w.broker.IdPAccessToken, w.log, w.o)
	reason := "downstream API " + a.downstream.resource + "; access tokens are capped at the stored IdP token's expiry"
	if w.cfg.UpstreamCommand != nil {
		w.log.Info("On-Behalf-Of", "reason", reason+"; each stdio process asks its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET)")
		return nil
	}
	w.log.Info("On-Behalf-Of", "reason", reason, "setting", "BYWARD_OBO_HEADER", "value", w.cfg.OBOHeader)
	return nil
}
