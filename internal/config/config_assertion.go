package config

import (
	"slices"
	"strconv"
	"strings"
)

// AssertionClaimNames are the optional claims an identity assertion may carry.
var AssertionClaimNames = []string{"roles", "groups", "email", "name"}

// assertion reads the identity assertion settings: a header that is a valid token and not one the
// proxy relies on, and claims from AssertionClaimNames (or none).
func (c *Config) assertion(v *Values) []error {
	var errs []error
	var err error
	if c.AssertionHeader, err = upstreamHeader(v, "assertion-header", "X-Byward-Identity"); err != nil {
		errs = append(errs, err)
	}
	ihEnv := Setting{Name: "identity-headers"}.Env()
	if c.IdentityHeaders, err = strconv.ParseBool(v.get("identity-headers")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", ihEnv, v.get("identity-headers")))
	} else if c.IdentityHeaders && c.UpstreamCommand != nil {
		errs = append(errs, errorf("%s is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)", ihEnv))
	}
	if c.AssertionUnverifiedEmail, err = strconv.ParseBool(v.get("assertion-unverified-email")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "assertion-unverified-email"}.Env(), v.get("assertion-unverified-email")))
	}
	cEnv := Setting{Name: "assertion-claims"}.Env()
	raw := strings.TrimSpace(v.get("assertion-claims"))
	if raw == "none" {
		return errs
	}
	seen := map[string]bool{}
	for _, name := range splitList(raw) {
		name = strings.ToLower(name)
		switch {
		case !slices.Contains(AssertionClaimNames, name):
			errs = append(errs, errorf("%s: %q is not one of %s, or none", cEnv, name, strings.Join(AssertionClaimNames, ", ")))
		case !seen[name]:
			seen[name] = true
			c.AssertionClaims = append(c.AssertionClaims, name)
		}
	}
	if raw != "" && len(splitList(raw)) == 0 {
		errs = append(errs, errorf("%s is set but lists nothing; give claims, or none", cEnv))
	}
	return errs
}
