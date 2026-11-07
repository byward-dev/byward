package server

import (
	"errors"
	"strings"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/gate"
)

// gateSettings maps gate rule lists to the settings that fill them; config owns the names.
var gateSettings = map[string]string{
	gate.FieldTenants:       config.Setting{Name: "gate-tenants"}.Env(),
	gate.FieldRoles:         config.Setting{Name: "gate-roles"}.Env(),
	gate.FieldGroups:        config.Setting{Name: "gate-groups"}.Env(),
	gate.FieldEmailDomains:  config.Setting{Name: "gate-email-domains"}.Env(),
	gate.FieldHostedDomains: config.Setting{Name: "gate-hosted-domains"}.Env(),
	gate.FieldAllowEmpty:    config.Setting{Name: "gate-allow-empty"}.Env(),
	gate.FieldAppRoles:      config.Setting{Name: "app-roles"}.Env(),
	gate.FieldAppClientIDs:  config.Setting{Name: "app-client-ids"}.Env(),
}

// gateError names the setting at fault for each invalid gate rule list.
func gateError(err error) error {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		var fe *gate.FieldError
		if errors.As(e, &fe) && gateSettings[fe.Field] != "" {
			msgs = append(msgs, gateSettings[fe.Field]+": "+fe.Msg)
			continue
		}
		msgs = append(msgs, "access gate: "+e.Error())
	}
	return errors.New(strings.Join(msgs, "; "))
}
