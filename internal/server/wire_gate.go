package server

import (
	"errors"
	"strings"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/gate"
)

// gateSettings maps gate rule lists to the settings that fill them, by name; config names each as the
// operator gave it (#623).
var gateSettings = map[string]string{
	gate.FieldTenants:       "gate-tenants",
	gate.FieldRoles:         "gate-roles",
	gate.FieldGroups:        "gate-groups",
	gate.FieldEmailDomains:  "gate-email-domains",
	gate.FieldHostedDomains: "gate-hosted-domains",
	gate.FieldAllowEmpty:    "gate-allow-empty",
	gate.FieldAppRoles:      "app-roles",
	gate.FieldAppClientIDs:  "app-client-ids",
}

// gateError names the setting at fault for each invalid gate rule list, as the operator gave it.
func gateError(cfg *config.Config, err error) error {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		var fe *gate.FieldError
		if errors.As(e, &fe) && gateSettings[fe.Field] != "" {
			msgs = append(msgs, cfg.Values.NameAsGiven(gateSettings[fe.Field])+": "+fe.Msg)
			continue
		}
		msgs = append(msgs, "access gate: "+e.Error())
	}
	return errors.New(strings.Join(msgs, "; "))
}
