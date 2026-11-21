package config

import (
	"slices"
	"strings"
)

// AssertionClaimNames are the optional claims an identity assertion may carry.
var AssertionClaimNames = []string{"roles", "groups", "email", "name"}

// assertion reads the identity assertion settings: a header that is a valid token and not one the
// proxy relies on, and claims from AssertionClaimNames (or none).
func (c *Config) assertion(v *Values) []error {
	var errs []error
	var err error
	if c.AssertionHeader, err = parseHeaderName(v.value("assertion-header")); err != nil {
		errs = append(errs, err)
	}
	ihEnv := Setting{Name: "identity-headers"}.Env()
	if c.IdentityHeaders, err = v.boolean("identity-headers"); err != nil {
		errs = append(errs, err)
	} else if c.IdentityHeaders && v.stdioUpstream() {
		errs = append(errs, errorf("%s is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)", ihEnv))
	}
	if c.AssertionUnverifiedEmail, err = v.boolean("assertion-unverified-email"); err != nil {
		errs = append(errs, err)
	}
	claims, claimErrs := parseAssertionClaims(v.value("assertion-claims"))
	c.AssertionClaims = claims
	return append(errs, claimErrs...)
}

// parseAssertionClaims reads BYWARD_ASSERTION_CLAIMS: claims from AssertionClaimNames, in any case, or
// none. A refused entry is never shown (ADR-0031 §1).
func parseAssertionClaims(val Value) ([]string, []error) {
	raw := strings.TrimSpace(val.Given.raw())
	if raw == "none" {
		return nil, nil
	}
	want := "claims from " + oneOf(AssertionClaimNames) + ", or none"
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	var out []string
	var errs []error
	for i, name := range list {
		switch name = strings.ToLower(name); {
		case name == "none" && len(list) == 1: // none alone, but not as written: in another case, or with a ","
			errs = append(errs, refusedMeaning(val.Setting, at(i), "none", want, "give none in lower case, with nothing beside it"))
		case name == "none": // a fixed word, so shown
			errs = append(errs, refusedMeaning(val.Setting, at(i), "none", want, "none stands alone: list claims, or give only none"))
		case !slices.Contains(AssertionClaimNames, name):
			errs = append(errs, refusedForm(val.Setting, at(i), name, want, "it is not one of them"))
		case !slices.Contains(out, name):
			out = append(out, name)
		}
	}
	return out, errs
}
