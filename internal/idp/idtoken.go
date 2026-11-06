package idp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Leeway is the clock skew allowed on exp/iat/nbf (ADR-0006, ADR-0014).
const Leeway = 30 * time.Second

// IDTokenRules are the per-IdP inputs to ID token validation (OIDC Core §3.1.3.7, ADR-0011 §5).
type IDTokenRules struct {
	// Issuer checks `iss` given all claims; it must compare exactly.
	Issuer   func(iss string, claims map[string]any) error
	ClientID string
	// Nonce must match when non-empty (always at login; empty on refresh).
	Nonce string
	// Algs is the allowlist; HS* and none are refused regardless.
	Algs []jose.SignatureAlgorithm
	Now  func() time.Time
}

// VerifyIDToken checks the signature against keys and the claims against r, and returns the claims.
func VerifyIDToken(ctx context.Context, raw string, keys *KeySet, r IDTokenRules) (map[string]any, error) {
	algs := make([]jose.SignatureAlgorithm, 0, len(r.Algs))
	for _, a := range r.Algs {
		if a != jose.HS256 && a != jose.HS384 && a != jose.HS512 && a != "none" {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return nil, errors.New("idp: no signature algorithm allowed")
	}
	tok, err := jwt.ParseSigned(raw, algs)
	if err != nil {
		return nil, fmt.Errorf("idp: ID token: %w", err)
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("idp: ID token must have one signature")
	}
	key, err := keys.Key(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := tok.Claims(key.Key, &claims); err != nil {
		return nil, fmt.Errorf("idp: ID token signature: %w", err)
	}
	if err := checkClaims(claims, r); err != nil {
		return nil, err
	}
	return claims, nil
}

func checkClaims(c map[string]any, r IDTokenRules) error {
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

// CodeChallenge is the PKCE S256 challenge for verifier.
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
