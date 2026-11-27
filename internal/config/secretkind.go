package config

import (
	"strings"

	"github.com/byward-dev/byward/internal/logging"
)

// parseSecretKinds refuses every setting that is not secret but would show a secret: one whose value,
// as its shape shows it in --print-config and the startup log, holds a secret's kind
// (logging.ShownSecretKind), a list setting's read entry by entry (logging.ShownListSecretKind).
// What a shape leaves out, a URL's user part or a command's arguments, is never shown, so never
// checked. A refusal names the setting as given and the kind, never the value (#495).
func parseSecretKinds(v *Values) []error {
	var errs []error
	for _, val := range v.Effective() {
		if val.Setting.Secret() || val.Source == SourceDefault {
			continue
		}
		var kind string
		if val.Setting.IsList() {
			kind = logging.ShownListSecretKind(strings.Split(val.Display(), ","))
		} else {
			kind = logging.ShownSecretKind(val.Display())
		}
		if kind != "" {
			errs = append(errs, secretKindRefusal(val, kind))
		}
	}
	return errs
}

// CheckShown refuses shown, the text a command other than the proxy prints for the setting name,
// when that text holds a secret's kind (logging.ShownSecretKind), as Load refuses one: naming the
// setting by its variable, as init's other refusals do, and the kind, never the value. The command passes what it prints,
// which can be more than the setting's shape shows: init entra writes --upstream-url whole into its
// script (#641).
func CheckShown(name, shown string) error {
	kind := logging.ShownSecretKind(shown)
	if kind == "" {
		return nil
	}
	return secretKindRefusal(Value{Setting: lookup(name), Given: NewOpaque(shown), Source: SourceEnv}, kind)
}

// secretKindRefusal is the refusal of val, whose value shows a secret of kind (#495).
func secretKindRefusal(val Value, kind string) error {
	return refusedForm(val, whole, val.Given.raw(), "a value that is not a secret (give a secret only in a secret setting's file)", "it looks like "+kind)
}
