package entra

import (
	"regexp"
	"strconv"

	"github.com/corker/mcp-authproxy/internal/idp"
)

// Codes whose class ADR-0012 §6 fixes.
var (
	signInAgainCodes   = map[int]bool{700082: true, 70043: true, 50076: true, 65001: true}
	invalidClientCodes = map[int]bool{7000222: true, 7000215: true, 700016: true, 5002723: true, 700027: true}
)

type page struct{ user, operator string }

// pages are the friendly error pages of ADR-0012 §7; error_description is never shown raw.
var pages = map[int]page{
	50020: {"Your account is not from the organisation this service belongs to.",
		"AADSTS50020: the user's home tenant is not allowed; check the tenant setting or invite the user as a guest."},
	50105: {"You have not been given access to this service. Ask its administrator to assign you.",
		"AADSTS50105: assignment is required on the enterprise application; assign the user or a group."},
	65001: {"This service has not been approved in your organisation yet. Ask its administrator.",
		"AADSTS65001: consent missing; grant admin consent for the app's API permissions."},
	50011: {"The service is misconfigured. Tell its administrator.",
		"AADSTS50011: the redirect URI is not registered; add https://<proxy>/callback/entra to the app registration (Web platform)."},
	53003: {"Your organisation's access policy blocked this sign-in.",
		"AADSTS53003: blocked by Conditional Access; check the sign-in log for the policy."},
	700016: {"The service is misconfigured. Tell its administrator.",
		"AADSTS700016: the client ID is not registered in this tenant; check the client ID and tenant."},
	7000222: {"The service is temporarily unavailable. Tell its administrator.",
		"AADSTS7000222: the client secret has expired; create a new one (or switch to a certificate)."},
	90072: {"Your account cannot sign in to this organisation. Ask its administrator to invite you.",
		"AADSTS90072: the external account does not exist in this tenant; invite it as a guest."},
}

var aadstsPrefix = regexp.MustCompile(`^AADSTS(\d+):`)

// codeOf takes the first error_codes entry, or the AADSTS prefix of error_description.
func codeOf(codes []int, description string) int {
	if len(codes) > 0 {
		return codes[0]
	}
	if m := aadstsPrefix.FindStringSubmatch(description); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// classify maps an Entra error to the broker's action (ADR-0012 §6).
func classify(status int, oauth string, code int) (idp.Class, bool) {
	switch {
	case invalidClientCodes[code] || oauth == "invalid_client":
		return idp.Unavailable, true
	case signInAgainCodes[code]:
		return idp.SignInAgain, false
	}
	return idp.GenericClass(status, oauth), false
}

func newError(status int, oauth, description string, codes []int, trace, corr string) *idp.Error {
	code := codeOf(codes, description)
	class, alert := classify(status, oauth, code)
	e := &idp.Error{Class: class, OAuth: oauth, Code: code, Status: status, TraceID: trace, CorrelationID: corr,
		Alert: alert, Description: description, UserMessage: "Sign-in failed. Try again, or tell the service's administrator."}
	if pg, ok := pages[code]; ok {
		e.UserMessage, e.OperatorHint = pg.user, pg.operator
	}
	return e
}
