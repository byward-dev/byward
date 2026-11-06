package entra

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// Setup is the input of the app registration script `byward init entra` prints (ADR-0020 §8).
type Setup struct {
	Tenant string
	// PublicURL and UpstreamURL (empty when not known) set PUBLIC_URL and UPSTREAM_URL for EnvFile.
	PublicURL, UpstreamURL string
	// RedirectURL is https://<proxy>/callback/entra, derived from the public URL as the proxy does.
	RedirectURL string
	// EnvFile is the env file the script writes last, with $TENANT_ID, $APP_ID, $SECRET_FILE,
	// $SECRET_EXPIRES_AT, $PUBLIC_URL and $UPSTREAM_URL expanded by the shell.
	EnvFile string
	// SecretYears is the client secret's lifetime; Entra allows at most two years (ADR-0012).
	SecretYears int
	Now         time.Time
}

// Roles the script defines (ADR-0022 §6): one users are assigned with, one for app-only callers.
const (
	UserRole = "byward.user"
	AppRole  = "byward.app"
)

// SecretFile is where the script writes the client secret, mode 0600.
const SecretFile = "entra-client-secret" //nolint:gosec // G101: a file name, not a credential

// MaxSecretYears is Entra's limit for client secrets ("limited to two years", ADR-0012).
const MaxSecretYears = 2

// SetupScript is the shell script that creates the app registration with `az` (ADR-0012 §12,
// ADR-0022 §6). byward never runs it and never sees the secret: the script writes the secret
// straight to SecretFile, then writes EnvFile to byward.env (mode 0600). The secret's end date is the
// date SecretYears from Now, at most a day early.
func SetupScript(s Setup) (string, error) {
	if !isGUID(s.Tenant) {
		return "", errors.New("the tenant must be the tenant ID, a GUID (az account show --query tenantId -o tsv)")
	}
	if s.SecretYears < 1 || s.SecretYears > MaxSecretYears {
		return "", fmt.Errorf("the secret lifetime must be 1 to %d years", MaxSecretYears)
	}
	var b strings.Builder
	err := setupTemplate.Execute(&b, map[string]any{
		"Tenant":      strings.ToLower(s.Tenant),
		"PublicURL":   shellQuote(s.PublicURL),
		"UpstreamURL": s.UpstreamURL,
		"Upstream":    shellQuote(s.UpstreamURL),
		"EnvFile":     s.EnvFile,
		"RedirectURL": shellQuote(s.RedirectURL),
		"Years":       s.SecretYears,
		"Expires":     s.Now.UTC().AddDate(s.SecretYears, 0, 0).Format(time.DateOnly),
		"SecretFile":  SecretFile,
		"UserRole":    UserRole,
		"AppRole":     AppRole,
	})
	return b.String(), err
}

// shellQuote quotes s for a POSIX shell: nothing inside single quotes is expanded.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// The commands follow docs/how-to/quickstart-entra.md step 1, which was run against a real tenant.
var setupTemplate = template.Must(template.New("setup").Parse(`#!/bin/sh
# Printed by byward init entra. byward has run none of it and never sees the client secret.
# Review it, save it as byward-entra.sh and run it with the Azure CLI signed in to the tenant:
#   az login --tenant {{.Tenant}} && sh byward-entra.sh
# Each run creates a new app registration named byward.
set -eu
PUBLIC_URL={{.PublicURL}}
{{if .UpstreamURL}}UPSTREAM_URL={{.Upstream}}
{{end}}
# 1. The app registration: this tenant only, the proxy's redirect URI (Web platform).
TENANT_ID={{.Tenant}}
REDIRECT_URI={{.RedirectURL}}
if [ "$(az account show --query tenantId -o tsv)" != "$TENANT_ID" ]; then
  echo "az is signed in to another tenant; run: az login --tenant $TENANT_ID" >&2
  exit 1
fi
APP_ID=$(az ad app create --display-name byward --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "$REDIRECT_URI" --query appId -o tsv)

# 2. One Microsoft Graph request, since az ad app has no flag for exposed scopes: the Application
#    ID URI, the access_as_user scope with v2 tokens, an app role for users and one for
#    applications (app-only callers), and the idtyp claim on access tokens.
SCOPE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
USER_ROLE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
APP_ROLE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
cat > byward-api.json <<EOF
{
  "identifierUris": ["api://$APP_ID"],
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [{
      "id": "$SCOPE_ID",
      "value": "access_as_user",
      "type": "User",
      "isEnabled": true,
      "adminConsentDisplayName": "Use MCP servers behind byward",
      "adminConsentDescription": "Lets byward sign users in and call MCP servers on their behalf.",
      "userConsentDisplayName": "Use MCP servers behind byward",
      "userConsentDescription": "Lets byward sign you in and call MCP servers on your behalf."
    }]
  },
  "appRoles": [{
    "id": "$USER_ROLE_ID",
    "value": "{{.UserRole}}",
    "allowedMemberTypes": ["User"],
    "displayName": "byward user",
    "description": "May use the MCP servers behind byward.",
    "isEnabled": true
  }, {
    "id": "$APP_ROLE_ID",
    "value": "{{.AppRole}}",
    "allowedMemberTypes": ["Application"],
    "displayName": "byward application",
    "description": "May call the MCP servers behind byward without a user.",
    "isEnabled": true
  }],
  "optionalClaims": {"accessToken": [{"name": "idtyp"}]}
}
EOF
az rest --method patch --url "https://graph.microsoft.com/v1.0/applications(appId='$APP_ID')" --body @byward-api.json
rm byward-api.json

# 3. The OpenID Connect permissions (Microsoft Graph openid, profile, email, offline_access).
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 37f7f235-527c-4136-accd-4a02d197296e=Scope 14dad69e-099b-42c9-810b-d002981feec1=Scope \
  64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0=Scope 7427e0e9-2fba-42fe-b0c0-848c9e6a8182=Scope

# 4. The service principal, with assignment required: only users, groups and applications you
#    assign (with {{.UserRole}} or {{.AppRole}}) can get tokens.
az ad sp create --id "$APP_ID" --query id -o tsv
az ad sp update --id "$APP_ID" --set appRoleAssignmentRequired=true

# 5. The client secret, straight into a 0600 file; it is never shown. --append keeps any existing
#    credentials of the app.
SECRET_FILE="$PWD/{{.SecretFile}}"
(umask 077; az ad app credential reset --id "$APP_ID" --append --display-name byward --years {{.Years}} \
  --query password -o tsv > "$SECRET_FILE")
SECRET_EXPIRES_AT={{.Expires}}

# 6. The env file: the settings the proxy needs, and the secret's end date so that the proxy and
#    byward doctor warn before it expires.
(umask 077; cat > byward.env <<EOF
{{.EnvFile}}EOF
)
echo "Created app registration $APP_ID; the secret is in $SECRET_FILE, the settings in byward.env."
echo "Next: assign users or groups to the enterprise application byward with the {{.UserRole}} role,"
echo "create a sealing key and an assertion key (docs/how-to/quickstart-entra.md step 2), start the proxy, then run byward doctor."
`))
