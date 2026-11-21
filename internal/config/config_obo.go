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
	var scopeErrs []error
	c.OBOScopes, scopeErrs = parseOBOScopes(v.value("obo-scopes"))
	errs = append(errs, scopeErrs...)
	if v.stdioUpstream() && v.byKey["obo-header"].Source != SourceDefault {
		errs = append(errs, errorf("%s: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave %s unset", hEnv, hEnv))
	}
	if len(c.OBOScopes) > 0 && c.IdP != "" && c.IdP != "entra" { // a refused IdP has its own error
		errs = append(errs, errorf("%s: On-Behalf-Of is Entra's; it needs BYWARD_IDP=entra, got %s", sEnv, c.IdP))
	}
	h, err := parseHeaderName(v.value("obo-header"))
	if err != nil {
		return append(errs, err)
	}
	c.OBOHeader = h
	// Authorization is allowed once the assertion and the upstream credential use other headers:
	// the client's own Authorization is always removed before byward sets its headers (#195).
	switch {
	case sameHeader(h, c.AssertionHeader):
		errs = append(errs, errorf("%s names the header that already carries the identity assertion (%s); move the assertion to a header of its own%s, or use another header here%s",
			hEnv, Setting{Name: "assertion-header"}.Env(), suchAs("assertion-header", h), suchAs("obo-header", h)))
	case sameHeader(h, c.UpstreamCredentialHeader):
		errs = append(errs, errorf("%s names the header that already carries the operator's upstream credential (%s); use a header of its own%s", hEnv, Setting{Name: "upstream-credential-header"}.Env(), suchAs("obo-header", h)))
	}
	return errs
}

// parseOBOScopes reads BYWARD_OBO_SCOPES: space-separated full scope URIs of one downstream API. A
// scope refused for its form is never shown (ADR-0031 §1), and two scopes for different APIs are
// named by their places in the list.
func parseOBOScopes(val Value) ([]string, []error) {
	s, raw := val.Setting, val.Given.raw()
	const want = "scope URIs of one API such as https://graph.microsoft.com/User.Read, api://<app>/<scope> or <app ID>/<scope>"
	scopes := strings.Fields(raw)
	if raw != "" && len(scopes) == 0 {
		return nil, []error{listsNothing(s)}
	}
	var errs []error
	resource, first := "", 0
	for i, sc := range scopes {
		at, j := entry{i, len(scopes)}, scopeSlash(sc)
		switch {
		case oidcScopes[strings.ToLower(sc)]:
			errs = append(errs, refusedMeaning(s, at, strings.ToLower(sc), want, "it is a sign-in scope, not a downstream API's; give the API's scopes, e.g. https://graph.microsoft.com/User.Read"))
		case j < 0:
			errs = append(errs, refusedForm(s, at, sc, want, "it is not a scope URI"))
		case resource == "":
			resource, first = sc[:j], i
		case sc[:j] != resource:
			errs = append(errs, refusedMeaning(s, whole, entry{first, len(scopes)}.and(at), want, "they are for different APIs; Entra issues a token for one API per request"))
		}
	}
	return scopes, errs
}
