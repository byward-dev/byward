package entra

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/idp"
)

// VerifyApp checks an Entra app-only access token that a headless caller sends the MCP endpoint
// (ADR-0022 §3): signed by the tenant's keys with RS256 and header typ JWT; iss the v2 issuer of
// an allowed tenant; aud our client ID only; exp, iat and nbf within the leeway; idtyp app and no
// scp, so a user's delegated token is never accepted here. The app's roles are returned for the
// access gate to judge.
//
// Errors wrap idp.ErrAppTokenExpired or idp.ErrNotAppOnly where they apply, and
// idp.ErrKeysUnavailable when the tenant's keys could not be fetched.
func (p *Provider) VerifyApp(ctx context.Context, raw string) (idp.App, error) {
	c, err := idp.VerifyTypedSignature(ctx, raw, p.keys, []jose.SignatureAlgorithm{jose.RS256}, "JWT")
	if err != nil {
		return idp.App{}, err
	}
	if err := p.checkIssuer(idp.StringClaim(c, "iss"), c); err != nil {
		return idp.App{}, err
	}
	if !onlyAudience(c["aud"], p.cfg.ClientID) {
		return idp.App{}, errors.New("entra: app-only token audience is not our client only")
	}
	now := p.cfg.Now()
	exp, ok := idp.TimeClaim(c, "exp")
	if !ok {
		return idp.App{}, errors.New("entra: app-only token has no exp")
	}
	if !now.Before(exp.Add(idp.Leeway)) {
		return idp.App{}, idp.ErrAppTokenExpired
	}
	iat, ok := idp.TimeClaim(c, "iat")
	if !ok || iat.After(now.Add(idp.Leeway)) {
		return idp.App{}, errors.New("entra: app-only token iat missing or in the future")
	}
	if nbf, ok := idp.TimeClaim(c, "nbf"); ok && nbf.After(now.Add(idp.Leeway)) {
		return idp.App{}, errors.New("entra: app-only token not yet valid")
	}
	// idtyp is "the most accurate way" to tell app-only from delegated; scp is only on delegated
	// tokens. Either one wrong is a user's token (ADR-0022 Context).
	if _, scp := c["scp"]; scp || idp.StringClaim(c, "idtyp") != "app" {
		return idp.App{}, idp.ErrNotAppOnly
	}
	// GUIDs in lower case, as user keys are stored (UserKey).
	tid, oid := strings.ToLower(idp.StringClaim(c, "tid")), strings.ToLower(idp.StringClaim(c, "oid"))
	azp := strings.ToLower(idp.StringClaim(c, "azp"))
	if !isGUID(oid) || !isGUID(azp) || !strings.EqualFold(idp.StringClaim(c, "sub"), oid) {
		return idp.App{}, errors.New("entra: app-only token oid, sub or azp is not the service principal's GUID")
	}
	roles, err := stringList(c["roles"])
	if err != nil {
		return idp.App{}, err
	}
	return idp.App{Tenant: tid, ObjectID: oid, ClientID: azp, Roles: roles, TokenID: idp.StringClaim(c, "uti"), IssuedAt: iat, Expiry: exp}, nil
}

// onlyAudience is aud naming our client and nothing else.
func onlyAudience(aud any, clientID string) bool {
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []any:
		return len(a) == 1 && a[0] == clientID
	}
	return false
}

// stringList is an absent claim (no roles) or an array of strings; anything else is malformed.
func stringList(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("entra: app-only token roles is not an array")
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("entra: app-only token roles holds a %T", e)
		}
		out = append(out, s)
	}
	return out, nil
}
