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
			errs = append(errs, refusedForm(val, whole, val.Given.raw(), "a value that is not a secret (give a secret only in a secret setting's file)", "it looks like "+kind))
		}
	}
	return errs
}
