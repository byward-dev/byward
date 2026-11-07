package entra

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/idp"
)

// grantJWTBearer is the On-Behalf-Of grant (RFC 7523 with Entra's requested_token_use).
const grantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: a grant-type URN, not a credential

// The Entra errors On-Behalf-Of turns into answers of their own (ADR-0017 §5).
const (
	CodeConsentRequired     = 65001 // the downstream API's permissions are not consented
	OAuthInteractionNeeded  = "interaction_required"
	downstreamOperatorHint  = "grant admin consent for the downstream API's permissions (the admin-consent URL is in this log record)"
	interactionOperatorHint = "Conditional Access requires interaction for the downstream API (claims challenge); passing it to the client's next sign-in is not supported yet"
)

// DownstreamToken is an access token for a downstream API, obtained On-Behalf-Of a user. It is
// opaque to byward: the downstream API validates it.
type DownstreamToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

// OnBehalfOf exchanges a user's access_as_user token (the assertion, ADR-0012 §3) for a token for
// the downstream API's scopes, at the user's own tenant (tid), so multi-tenant apps work too. An
// Entra error comes back as *idp.Error with its AADSTS Code and OAuth error: CodeConsentRequired
// and OAuthInteractionNeeded carry operator hints; the claims challenge is never kept.
func (p *Provider) OnBehalfOf(ctx context.Context, tid, assertion string, scopes []string) (DownstreamToken, error) {
	if !isGUID(tid) || assertion == "" || len(scopes) == 0 {
		return DownstreamToken{}, &idp.Error{Class: idp.Fatal, Err: errors.New("entra: On-Behalf-Of needs a tenant GUID, an assertion and scopes")}
	}
	if err := p.Ready(ctx); err != nil {
		return DownstreamToken{}, err
	}
	tr, err := p.tokenAt(ctx, tid, url.Values{
		"grant_type":          {grantJWTBearer},
		"requested_token_use": {"on_behalf_of"},
		"assertion":           {assertion},
		"scope":               {strings.Join(scopes, " ")},
	})
	if err != nil {
		var ie *idp.Error
		if errors.As(err, &ie) {
			switch {
			case ie.Code == CodeConsentRequired:
				ie.OperatorHint = "AADSTS65001: " + downstreamOperatorHint
			case ie.OAuth == OAuthInteractionNeeded:
				ie.OperatorHint = interactionOperatorHint
			}
		}
		return DownstreamToken{}, err
	}
	if tr.AccessToken == "" || tr.ExpiresIn <= 0 || !strings.EqualFold(tr.TokenType, "Bearer") {
		return DownstreamToken{}, &idp.Error{Class: idp.Fatal, Err: errors.New("entra: On-Behalf-Of returned no usable bearer token")}
	}
	return DownstreamToken{AccessToken: tr.AccessToken, ExpiresAt: p.cfg.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)}, nil
}

// AdminConsentURL is where an administrator of tenant tid grants our app the downstream scopes
// (Microsoft identity platform admin consent, v2). The redirect is our registered callback.
func (p *Provider) AdminConsentURL(tid string, scopes []string) string {
	q := url.Values{
		"client_id":    {p.cfg.ClientID},
		"scope":        {strings.Join(scopes, " ")},
		"redirect_uri": {p.cfg.RedirectURL},
	}
	return Authority + "/" + url.PathEscape(tid) + "/v2.0/adminconsent?" + q.Encode()
}
