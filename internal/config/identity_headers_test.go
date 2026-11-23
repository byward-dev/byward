package config

import (
	"strings"
	"testing"
)

func TestPlainIdentityHeadersAreOffUntilSetTrue(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentityHeaders {
		t.Fatal("plain identity headers are on by default")
	}
	if c, err = load(t, nil, "BYWARD_IDENTITY_HEADERS=true"); err != nil || !c.IdentityHeaders {
		t.Fatalf("BYWARD_IDENTITY_HEADERS=true: on %v, err %v", c != nil && c.IdentityHeaders, err)
	}
	// A bare flag turns it on, as for every other boolean setting.
	if c, err = load(t, []string{"--identity-headers"}); err != nil || !c.IdentityHeaders {
		t.Fatalf("--identity-headers: on %v, err %v", c != nil && c.IdentityHeaders, err)
	}
}

// The plain identity headers need an authenticated user and an HTTP upstream.
func TestPlainIdentityHeadersRefuseWhatCannotWork(t *testing.T) {
	entra := []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001",
		"BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002", "BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra"}
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		inErr string
	}{
		{"without authentication", nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
			"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_IDENTITY_HEADERS=true"},
			"BYWARD_INSECURE_NO_AUTH cannot be combined with BYWARD_IDENTITY_HEADERS: remove one of them"},
		{"a stdio upstream", []string{"--", "/usr/local/bin/server"}, append(entra, "BYWARD_IDENTITY_HEADERS=true"),
			"BYWARD_IDENTITY_HEADERS is for an HTTP upstream; a stdio upstream gets the user in its environment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(tc.args, tc.env, baseFiles); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
}

// The plain identity headers' names are reserved whether or not they are on: the assertion and the
// credential cannot use them, in any spelling (ADR-0016 §5).
func TestNoOtherSettingMayUseAPlainIdentityHeader(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   []string
		inErr string
	}{
		{"the assertion, headers off", []string{"BYWARD_ASSERTION_HEADER=X-Byward-Roles"},
			"BYWARD_ASSERTION_HEADER: want a header name such as Authorization or X-Byward-Identity; got X-Byward-Roles: it is one of the plain identity headers the proxy sets"},
		{"the assertion, headers on", []string{"BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_HEADER=x-byward-subject"},
			"BYWARD_ASSERTION_HEADER: want a header name such as Authorization or X-Byward-Identity; got X-Byward-Subject: it is one of the plain identity headers the proxy sets"},
		{"the On-Behalf-Of header", []string{"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_OBO_HEADER=X-Byward-Roles"},
			"BYWARD_OBO_HEADER: want a header name such as Authorization or X-Byward-Downstream-Token; got X-Byward-Roles: it is one of the plain identity headers the proxy sets"},
		{"the credential, another spelling", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X_Byward_Email"},
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER: want a header name such as Authorization or X-Api-Key; got X-Byward-Email: it is one of the plain identity headers the proxy sets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadCred(t, nil, "k-123", tc.env...); err == nil || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want %q", err, tc.inErr)
			}
		})
	}
	for _, h := range IdentityHeaderNames { // every one, so a header added later is reserved too
		if _, err := loadCred(t, nil, "k-123", "BYWARD_ASSERTION_HEADER="+h); err == nil || !strings.Contains(err.Error(), "got "+h+": it is one of the plain identity headers the proxy sets") {
			t.Errorf("BYWARD_ASSERTION_HEADER=%s: err = %v, want it refused as a plain identity header", h, err)
		}
	}
}

// Beside a stdio upstream, every setting for an HTTP upstream is refused for any value given, true
// or false, as a flag or a variable: the HTTP upstream's own group, the identity assertion (httpOnly)
// and the two with a stdio hint of their own, the plain identity headers and the On-Behalf-Of header.
// Before #606, BYWARD_IDENTITY_HEADERS=false loaded, since its check read the value, not whether it
// was given. A variable set to nothing is unset (#428), so each loads that way. The settings are read
// from the registry, so one added to these groups is covered too; secrets take a file, not true or
// false, and the URL is the other mode's selector.
func TestEverySettingForAnHTTPUpstreamIsRefusedBesideStdioForAnyValueGiven(t *testing.T) {
	ownHint := map[string]string{
		"identity-headers": "BYWARD_IDENTITY_HEADERS is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)",
		"obo-header":       "BYWARD_OBO_HEADER: a stdio upstream gets its downstream token from its token socket",
	}
	n := 0
	for _, s := range registry {
		if s.Secret() || s.Name == "upstream-url" || s.Group != GroupHTTPUpstream && !httpOnly[s.Name] && ownHint[s.Name] == "" {
			continue
		}
		n++
		for _, value := range []string{"false", "true"} {
			for _, given := range []struct {
				how, name string
				args, env []string
			}{
				{"a variable", s.Env(), nil, []string{s.Env() + "=" + value}},
				{"a flag", "--" + s.Name, []string{"--" + s.Name + "=" + value}, nil},
			} {
				t.Run(s.Name+"/"+given.how+"/"+value, func(t *testing.T) {
					want := given.name + " is set, but the upstream is stdio"
					if h := ownHint[s.Name]; h != "" {
						want = h
						if s.Name == "obo-header" {
							want = strings.Replace(h, "BYWARD_OBO_HEADER", given.name, 1)
						}
					}
					_, _, err := Load(given.args, stdioBase(append([]string{stdioCommand}, given.env...)...), baseFiles)
					if !isConfigError(err) || !strings.Contains(err.Error(), want) {
						t.Fatalf("err = %v, want a config error containing %q", err, want)
					}
				})
			}
		}
		t.Run(s.Name+"/a variable set to nothing", func(t *testing.T) {
			if _, _, err := Load(nil, stdioBase(stdioCommand, s.Env()+"="), baseFiles); err != nil {
				t.Fatalf("%s= beside stdio: %v, want it to load as unset", s.Env(), err)
			}
		})
	}
	if n < 9 { // the HTTP upstream's 3, the assertion's 4, and the 2 with a hint of their own, today
		t.Fatalf("%d settings checked; want every one for an HTTP upstream (9 today)", n)
	}
}
