package assertion

import (
	"encoding/json"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// JWKS is the public half of every key, for verifiers.
func (k *Keys) JWKS() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(k.all))}
	for _, s := range k.all {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.id, Algorithm: string(jose.ES256), Use: "sig"})
	}
	return set
}

// JWKSHandler serves the JWKS at /.well-known/jwks.json (ADR-0016 §3).
func (k *Keys) JWKSHandler() http.Handler {
	body, err := json.Marshal(k.JWKS())
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}
