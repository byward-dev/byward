package config

import "strings"

// oidcScopes are login scopes, never a downstream API's.
var oidcScopes = map[string]bool{"openid": true, "profile": true, "email": true, "offline_access": true}

// scopeSlash is the index of the "/" that ends a scope's API part (https://graph.microsoft.com in
// https://graph.microsoft.com/User.Read), or -1 when s is not an API and a scope. The API is an
// https:// or api:// URI, or an app ID (a GUID), as for an API known by its application ID, e.g.
// AKS's server app 6dae42f8-4368-4678-94ff-3960e28e3630/.default (#196).
func scopeSlash(s string) int {
	if id, scope, ok := strings.Cut(s, "/"); ok && isGUID(id) && scope != "" && !strings.Contains(scope, "/") {
		return len(id)
	}
	for _, scheme := range []string{"https://", "api://"} {
		rest, ok := strings.CutPrefix(s, scheme)
		if !ok {
			continue
		}
		// The API part needs a host and no empty segment: https:///x/y and https://a//b are typos.
		if j := strings.LastIndex(rest, "/"); j > 0 && j < len(rest)-1 && rest[0] != '/' && !strings.Contains(rest, "//") {
			return len(scheme) + j
		}
	}
	return -1
}

// onBehalfOf reads the On-Behalf-Of settings (ADR-0017): full scope URIs of one downstream API, and
// a header of its own for an HTTP upstream. A stdio upstream asks a socket for its token instead,
// so a header set for it would have no effect.
func (c *Config) onBehalfOf(v *Values) []error {
	sEnv, hEnv := Setting{Name: "obo-scopes"}.Env(), Setting{Name: "obo-header"}.Env()
	var errs []error
	c.OBOScopes = strings.Fields(v.get("obo-scopes"))
	resource := ""
	for _, s := range c.OBOScopes {
		i := scopeSlash(s)
		switch {
		case oidcScopes[strings.ToLower(s)]:
			errs = append(errs, errorf("%s: %s is a sign-in scope, not a downstream API's; give the API's scopes, e.g. https://graph.microsoft.com/User.Read", sEnv, s))
		case i < 0:
			errs = append(errs, errorf("%s: %q is not a scope URI such as https://graph.microsoft.com/User.Read, api://<app>/<scope> or <app ID>/<scope>", sEnv, s))
		case resource == "":
			resource = s[:i]
		case s[:i] != resource:
			errs = append(errs, errorf("%s: %s and %s are for different APIs; Entra issues a token for one API per request", sEnv, resource, s[:i]))
		}
	}
	if v.get("obo-scopes") != "" && len(c.OBOScopes) == 0 {
		errs = append(errs, errorf("%s is set but lists nothing; give scopes, or leave it unset", sEnv))
	}
	if c.UpstreamCommand != nil && v.byKey["obo-header"].Source != SourceDefault {
		errs = append(errs, errorf("%s: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave %s unset", hEnv, hEnv))
	}
	if len(c.OBOScopes) > 0 && c.IdP != "entra" {
		errs = append(errs, errorf("%s: On-Behalf-Of is Entra's; it needs BYWARD_IDP=entra, got %s", sEnv, c.IdP))
	}
	h, err := upstreamHeader(v, "obo-header", "X-Byward-Downstream-Token")
	if err != nil {
		return append(errs, err)
	}
	c.OBOHeader = h
	// Authorization is allowed once the assertion and the upstream credential use other headers:
	// the client's own Authorization is always removed before byward sets its headers (#195).
	switch {
	case sameHeader(h, c.AssertionHeader):
		errs = append(errs, errorf("%s: %s already carries the identity assertion (%s); move the assertion to a header of its own such as X-Byward-Assertion, or use another header here such as X-Byward-Downstream-Token",
			hEnv, h, Setting{Name: "assertion-header"}.Env()))
	case sameHeader(h, c.UpstreamCredentialHeader):
		errs = append(errs, errorf("%s: %s already carries the operator's upstream credential (%s); use a header of its own such as X-Byward-Downstream-Token", hEnv, h, Setting{Name: "upstream-credential-header"}.Env()))
	}
	return errs
}
