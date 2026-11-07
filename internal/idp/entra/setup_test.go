package entra

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/fakeaz"
)

const setupTenant = "11111111-2222-3333-4444-555555555555"

var setupInput = Setup{Tenant: setupTenant, PublicURL: "https://mcp.example.com/mcp", RedirectURL: "https://mcp.example.com/callback/entra",
	EnvFile:     "BYWARD_ENTRA_CLIENT_ID=$APP_ID\nBYWARD_ENTRA_CLIENT_SECRET_FILE=$SECRET_FILE\nEXPIRES=$SECRET_EXPIRES_AT\n",
	SecretYears: 1, Now: time.Date(2026, 11, 6, 15, 0, 0, 0, time.UTC)}

func runSetup(t *testing.T, s Setup, signedInTenant string) fakeaz.Result {
	t.Helper()
	script, err := SetupScript(s)
	if err != nil {
		t.Fatal(err)
	}
	return fakeaz.Run(t, script, signedInTenant)
}

// The script registers the app as the quickstart does, plus what app-only callers need
// (ADR-0022 §6), in this order.
func TestSetupScriptRegistersTheAppWithTheAzureCLI(t *testing.T) {
	r := runSetup(t, setupInput, setupTenant)
	if r.Err != nil {
		t.Fatalf("script failed: %v\n%s", r.Err, r.Stderr)
	}
	app := fakeaz.AppID
	want := []string{
		"az account show --query tenantId -o tsv",
		"az ad app create --display-name byward --sign-in-audience AzureADMyOrg --web-redirect-uris https://mcp.example.com/callback/entra --query appId -o tsv",
		"az rest --method patch --url https://graph.microsoft.com/v1.0/applications(appId='" + app + "') --body @byward-api.json",
		"az ad app permission add --id " + app + " --api 00000003-0000-0000-c000-000000000000 --api-permissions 37f7f235-527c-4136-accd-4a02d197296e=Scope 14dad69e-099b-42c9-810b-d002981feec1=Scope 64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0=Scope 7427e0e9-2fba-42fe-b0c0-848c9e6a8182=Scope",
		"az ad sp create --id " + app + " --query id -o tsv",
		"az ad sp update --id " + app + " --set appRoleAssignmentRequired=true",
		"az ad app credential reset --id " + app + " --append --display-name byward --years 1 --query password -o tsv",
	}
	if !slices.Equal(r.Calls, want) {
		t.Fatalf("az calls\n%s\nwant\n%s", strings.Join(r.Calls, "\n"), strings.Join(want, "\n"))
	}
	if _, err := os.Stat(filepath.Join(r.Dir, "byward-api.json")); err == nil {
		t.Error("the Graph request body is left behind")
	}
}

func TestSetupScriptGraphRequestExposesTheScopeRolesAndIdtyp(t *testing.T) {
	var body struct {
		IdentifierURIs []string `json:"identifierUris"`
		API            struct {
			Version int `json:"requestedAccessTokenVersion"`
			Scopes  []struct {
				Value     string `json:"value"`
				IsEnabled bool   `json:"isEnabled"`
			} `json:"oauth2PermissionScopes"`
		} `json:"api"`
		AppRoles []struct {
			Value   string   `json:"value"`
			Members []string `json:"allowedMemberTypes"`
		} `json:"appRoles"`
		OptionalClaims struct {
			AccessToken []struct {
				Name string `json:"name"`
			} `json:"accessToken"`
		} `json:"optionalClaims"`
	}
	r := runSetup(t, setupInput, setupTenant)
	if err := json.Unmarshal([]byte(r.GraphBody), &body); err != nil {
		t.Fatalf("Graph body is not JSON: %v\n%s", err, r.GraphBody)
	}
	if !slices.Equal(body.IdentifierURIs, []string{"api://" + fakeaz.AppID}) || body.API.Version != 2 ||
		len(body.API.Scopes) != 1 || body.API.Scopes[0].Value != "access_as_user" || !body.API.Scopes[0].IsEnabled {
		t.Fatalf("Application ID URI, token version or scope wrong: %+v", body)
	}
	roles := map[string][]string{}
	for _, r := range body.AppRoles {
		roles[r.Value] = r.Members
	}
	if !slices.Equal(roles[UserRole], []string{"User"}) || !slices.Equal(roles[AppRole], []string{"Application"}) || len(roles) != 2 {
		t.Fatalf("app roles %v", roles)
	}
	if len(body.OptionalClaims.AccessToken) != 1 || body.OptionalClaims.AccessToken[0].Name != "idtyp" {
		t.Fatalf("optional claims %+v", body.OptionalClaims)
	}
}

// The secret goes into a 0600 file, never to the terminal; the env file names it and its end date.
func TestSetupScriptKeepsTheSecretInA0600File(t *testing.T) {
	for _, years := range []int{1, 2} {
		in := setupInput
		in.SecretYears = years
		r := runSetup(t, in, setupTenant)
		if r.Err != nil {
			t.Fatalf("script failed: %v\n%s", r.Err, r.Stderr)
		}
		secret, mode := r.File(t, SecretFile)
		if strings.TrimSpace(secret) != fakeaz.Secret || mode != 0o600 {
			t.Fatalf("secret file %q mode %v", secret, mode)
		}
		if strings.Contains(r.Stdout+r.Stderr, fakeaz.Secret) {
			t.Fatal("the secret was printed")
		}
		env, mode := r.File(t, "byward.env")
		wantEnv := "BYWARD_ENTRA_CLIENT_ID=" + fakeaz.AppID + "\nBYWARD_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(r.Dir, SecretFile) +
			"\nEXPIRES=" + in.Now.AddDate(years, 0, 0).Format(time.DateOnly) + "\n"
		if mode != 0o600 || env != wantEnv {
			t.Fatalf("byward.env mode %v:\n%s\nwant\n%s", mode, env, wantEnv)
		}
		if call := fmt.Sprintf("az ad app credential reset --id %s --append --display-name byward --years %d --query password -o tsv", fakeaz.AppID, years); !slices.Contains(r.Calls, call) {
			t.Fatalf("no %q in %v", call, r.Calls)
		}
	}
}

func TestSetupScriptStopsWhenAzIsSignedInToAnotherTenant(t *testing.T) {
	r := runSetup(t, setupInput, "99999999-9999-9999-9999-999999999999")
	if r.Err == nil || !strings.Contains(r.Stderr, "az login --tenant "+setupTenant) {
		t.Fatalf("err %v stderr %q", r.Err, r.Stderr)
	}
	if len(r.Calls) != 1 {
		t.Fatalf("the script went on after the tenant check: %v", r.Calls)
	}
}

func TestSetupScriptRefusesBadInput(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Setup)
		inErr  string
	}{
		{"tenant is a domain", func(s *Setup) { s.Tenant = "contoso.onmicrosoft.com" }, "tenant ID"},
		{"tenant is common", func(s *Setup) { s.Tenant = "common" }, "tenant ID"},
		{"secret for 0 years", func(s *Setup) { s.SecretYears = 0 }, "1 to 2 years"},
		{"secret for 3 years", func(s *Setup) { s.SecretYears = 3 }, "1 to 2 years"},
		{"an unknown credential", func(s *Setup) { s.Credential = "password" }, `the credential must be secret or certificate, not "password"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := setupInput
			tc.change(&in)
			if _, err := SetupScript(in); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}

// URLs a shell would expand stay literal, and nothing in them runs.
func TestSetupScriptNeverRunsShellCodeFromAURL(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	in := setupInput
	hostile := "/a$(touch pwned)'b`touch pwned2`"
	in.RedirectURL = "https://mcp.example.com" + hostile + "/callback/entra"
	in.PublicURL = "https://mcp.example.com" + hostile + "/mcp"
	in.UpstreamURL = "http://127.0.0.1:3001" + hostile
	in.EnvFile = "PUBLIC=$PUBLIC_URL\nUPSTREAM=$UPSTREAM_URL\n"
	r := runSetup(t, in, setupTenant)
	if r.Err != nil {
		t.Fatalf("script failed: %v\n%s", r.Err, r.Stderr)
	}
	if want := "az ad app create --display-name byward --sign-in-audience AzureADMyOrg --web-redirect-uris " + in.RedirectURL + " --query appId -o tsv"; r.Calls[1] != want {
		t.Fatalf("redirect URI reached az as\n%s\nwant\n%s", r.Calls[1], want)
	}
	if env, _ := r.File(t, "byward.env"); env != "PUBLIC="+in.PublicURL+"\nUPSTREAM="+in.UpstreamURL+"\n" {
		t.Fatalf("env file %q", env)
	}
	for _, f := range []string{"pwned", "pwned2"} {
		if _, err := os.Stat(filepath.Join(r.Dir, f)); err == nil {
			t.Fatal("the shell ran a command from a URL")
		}
	}
}

// With a certificate credential the script makes the key and a self-signed certificate on this
// machine, keeps them together in a 0600 file that byward loads as it is, uploads only the public
// certificate, and never prints the key (ADR-0012 §5).
func TestSetupScriptWithACertificateUploadsOnlyThePublicCertificate(t *testing.T) {
	if _, err := os.Stat("/usr/bin/openssl"); err != nil {
		t.Skip("the script runs the system openssl, and there is none at /usr/bin/openssl")
	}
	in := setupInput
	in.Credential = CredentialCertificate
	in.EnvFile = "BYWARD_ENTRA_CLIENT_ID=$APP_ID\nBYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=$CERTIFICATE_FILE\n"
	in.Now = time.Now()
	r := runSetup(t, in, setupTenant)
	if r.Err != nil {
		t.Fatalf("script failed: %v\n%s", r.Err, r.Stderr)
	}
	pemFile, mode := r.File(t, CertificateFile)
	if mode != 0o600 {
		t.Fatalf("certificate file mode %v", mode)
	}
	c, err := LoadCertificate([]byte(pemFile))
	if err != nil {
		t.Fatalf("byward refuses the file the script wrote: %v", err)
	}
	if c.Key.N.BitLen() != 2048 || c.X509.NotAfter.Before(time.Now().AddDate(1, 0, -2)) || c.X509.NotAfter.After(time.Now().AddDate(1, 0, 1)) {
		t.Fatalf("a %d-bit key, certificate until %s; want 2048 bits for a year", c.Key.N.BitLen(), c.X509.NotAfter)
	}
	upload := "az ad app credential reset --id " + fakeaz.AppID + " --append --display-name byward --cert @" + filepath.Join(r.Dir, CertificateFile) + ".crt"
	if !slices.Contains(r.Calls, upload) {
		t.Fatalf("no %q in\n%s", upload, strings.Join(r.Calls, "\n"))
	}
	for _, leftover := range []string{CertificateFile + ".key", CertificateFile + ".crt", SecretFile} {
		if _, err := os.Stat(filepath.Join(r.Dir, leftover)); err == nil {
			t.Errorf("%s is left behind", leftover)
		}
	}
	if strings.Contains(r.Stdout+r.Stderr, "PRIVATE KEY") {
		t.Fatal("the private key was printed")
	}
	env, _ := r.File(t, "byward.env")
	if want := "BYWARD_ENTRA_CLIENT_ID=" + fakeaz.AppID + "\nBYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=" + filepath.Join(r.Dir, CertificateFile) + "\n"; env != want {
		t.Fatalf("byward.env:\n%s\nwant\n%s", env, want)
	}
}

// The certificate lives as long as --secret-years says, counted in days across leap years.
func TestSetupScriptMakesTheCertificateForTheChosenYears(t *testing.T) {
	for years, days := range map[int]int{1: 365, 2: 731} { // 2026-11-06 to 2028-11-06 crosses 2028-02-29
		in := setupInput
		in.Credential, in.SecretYears = CredentialCertificate, years
		script, err := SetupScript(in)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("-days %d ", days); !strings.Contains(script, want) {
			t.Errorf("%d years: no %q in the script", years, want)
		}
	}
}
