package server

import (
	"fmt"
	"net/url"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp/entra"
)

// InitOptions is the input of `byward init <idp>`.
type InitOptions struct {
	IdP         string
	Tenant      string
	PublicURL   *url.URL
	UpstreamURL string // empty leaves BYWARD_UPSTREAM_URL for the operator to fill in
	SecretYears int
	Now         time.Time
}

// InitScript is the setup script `byward init` prints (ADR-0020 §8): the IdP's registration
// commands, ending in the minimal env file. Only Entra has one so far.
func InitScript(o InitOptions) (string, error) {
	if o.IdP != "entra" {
		return "", fmt.Errorf("init sets up only an entra IdP, not %q; for an oidc IdP see docs/how-to/oidc.md", o.IdP)
	}
	env := config.Quickstart{PublicURL: "$PUBLIC_URL", Tenant: "$TENANT_ID", ClientID: "$APP_ID",
		SecretFile: "$SECRET_FILE", SecretExpiresAt: "$SECRET_EXPIRES_AT"}
	if o.UpstreamURL != "" {
		env.UpstreamURL = "$UPSTREAM_URL"
	}
	return entra.SetupScript(entra.Setup{Tenant: o.Tenant, PublicURL: o.PublicURL.String(), UpstreamURL: o.UpstreamURL,
		RedirectURL: config.RedirectURL(o.PublicURL, "entra"), EnvFile: env.EnvFile(), SecretYears: o.SecretYears, Now: o.Now})
}
