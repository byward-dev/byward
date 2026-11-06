package idp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Leeway is the clock skew allowed on exp/iat/nbf (ADR-0006, ADR-0014).
const Leeway = 30 * time.Second

// TokenRules are the per-IdP inputs to JWT validation: ID tokens (OIDC Core §3.1.3.7, ADR-0011 §5)
// and, for Entra, our own v2 access_as_user access token, which needs the same iss, aud = client
// ID, azp, exp, iat and sub checks.
type TokenRules struct {
	// Issuer checks `iss` given all claims; it must compare exactly.
	Issuer   func(iss string, claims map[string]any) error
	ClientID string
	// Nonce must match when non-empty (always at login; empty on refresh).
	Nonce string
	// Algs is the allowlist; HS* and none are refused regardless.
	Algs []jose.SignatureAlgorithm
	Now  func() time.Time
}

// VerifyJWT checks an IdP-signed JWT's signature against keys and its claims against r, and returns
// the claims. Keep its checks valid for both token kinds named on TokenRules.
func VerifyJWT(ctx context.Context, raw string, keys KeySource, r TokenRules) (map[string]any, error) {
	claims, err := VerifySignature(ctx, raw, keys, r.Algs)
	if err != nil {
		return nil, err
	}
	if err := checkClaims(claims, r); err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifySignature checks a compact JWS against keys with an algorithm allowlist (HS* and none are
// always refused) and returns its claims unchecked; callers apply their own claim rules.
func VerifySignature(ctx context.Context, raw string, keys KeySource, allowed []jose.SignatureAlgorithm) (map[string]any, error) {
	algs := make([]jose.SignatureAlgorithm, 0, len(allowed))
	for _, a := range allowed {
		if a != jose.HS256 && a != jose.HS384 && a != jose.HS512 && a != "none" {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return nil, errors.New("idp: no signature algorithm allowed")
	}
	tok, err := jwt.ParseSigned(raw, algs)
	if err != nil {
		// go-jose's parse errors can quote header bytes, and a JWT here may be a credential.
		return nil, errors.New("idp: JWT is malformed or its alg is not allowed")
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("idp: JWT must have one signature")
	}
	key, err := keys.Key(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := tok.Claims(key.Key, &claims); err != nil {
		return nil, fmt.Errorf("idp: JWT signature: %w", err)
	}
	return claims, nil
}

func checkClaims(c map[string]any, r TokenRules) error {
	iss, _ := c["iss"].(string)
	if err := r.Issuer(iss, c); err != nil {
		return err
	}
	switch aud := c["aud"].(type) {
	case string:
		if aud != r.ClientID {
			return errors.New("idp: ID token audience is not our client")
		}
	case []any:
		// No audience besides ours is trusted (OIDC Core §3.1.3.7 step 3).
		if len(aud) != 1 || aud[0] != r.ClientID {
			return errors.New("idp: ID token audience must be our client only")
		}
	default:
		return errors.New("idp: ID token has no audience")
	}
	if azp, ok := c["azp"]; ok && azp != r.ClientID {
		return errors.New("idp: ID token azp is not our client")
	}
	now := r.Now()
	exp, ok := numericDate(c["exp"])
	if !ok || !now.Before(exp.Add(Leeway)) {
		return errors.New("idp: ID token expired")
	}
	iat, ok := numericDate(c["iat"])
	if !ok || iat.After(now.Add(Leeway)) {
		return errors.New("idp: ID token iat missing or in the future")
	}
	if nbf, ok := numericDate(c["nbf"]); ok && nbf.After(now.Add(Leeway)) {
		return errors.New("idp: ID token not yet valid")
	}
	if r.Nonce != "" {
		got, _ := c["nonce"].(string)
		if subtle.ConstantTimeCompare([]byte(got), []byte(r.Nonce)) != 1 {
			return errors.New("idp: ID token nonce mismatch")
		}
	}
	if s, _ := c["sub"].(string); s == "" {
		return errors.New("idp: ID token has no sub")
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// StringClaim returns a string claim or "".
func StringClaim(c map[string]any, k string) string {
	s, _ := c[k].(string)
	return s
}

// StringsClaim returns a string-array claim (non-strings dropped).
func StringsClaim(c map[string]any, k string) []string {
	raw, _ := c[k].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
