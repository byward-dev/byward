package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byward-dev/byward/internal/logging"
)

// shape is the kind of value a setting holds, which decides how the value is shown (ADR-0031 §3):
// display gives an accepted value as the startup log and --print-config show it, and refused gives what
// a refusal of a value for its form shows of it (refusedForm). display's result is one line of
// printable characters, whatever the value holds, so a value can never start a line of its own in
// --print-config (#505).
// Its identity also says what kind of value the setting holds: secretShape and pathShape (ADR-0031 §3
// as amended for #587).
// Every registry entry has one, which init checks; build one only with newShape.
type shape struct {
	display func(raw string) string
	refused func(raw string) string
}

// newShape is the only way to build a shape. It panics on a nil function, so a half-built shape
// stops the program at init, never at a request.
func newShape(display, refused func(raw string) string) *shape {
	if display == nil || refused == nil {
		panic("config: a shape needs both its display and its refused function")
	}
	return &shape{display: display, refused: refused}
}

// The shapes. A setting's shape is compared by identity: secretShape also means the setting is read
// only from a file (Setting.Secret), and pathShape that it holds a path (Setting.HoldsPath).
var (
	// secretShape is a secret: read only from a file and never shown.
	secretShape = newShape(func(string) string { return "<redacted>" }, notShown)
	// urlShape is a URL the proxy uses whole: shown by its scheme, host and path, with a marker for
	// each part left out, since a query can hold an API key (logging.MarkedURL, #458).
	urlShape = newShape(logging.MarkedURL, notShown)
	// urlListShape is a comma-separated list whose entries can be URLs: each URL entry is shown as
	// urlShape shows it, and any other entry as asGivenShape shows it.
	urlListShape = newShape(displayURLList, notShown)
	// listShape is a comma-separated list whose entries are not URLs: shown as given, as asGivenShape
	// is. It differs only by identity (Setting.IsList): no entry holds a comma, so a secret is
	// looked for in each entry on its own (parseSecretKinds).
	listShape = newShape(displayAsGiven, notShown)
	// commandShape is a command line as a JSON array: shown by its program and how many arguments
	// follow, since an argument can be a token (displayCommand).
	commandShape = newShape(displayCommand, notShown)
	// pathShape is a path the proxy reads or writes: shown as given, as asGivenShape is, since the
	// startup listing and --print-config show paths (#575). It differs only by identity
	// (Setting.HoldsPath): a file such a setting names that cannot be used is named by the setting and
	// the cause, never the path (security invariant 2, #587).
	pathShape = newShape(displayAsGiven, notShown)
	// asGivenShape is any other value: shown as given, quoted when it holds a character that is not
	// printable (displayAsGiven). A setting gets it by a reviewed decision
	// (TestTheSettingsOfEachShapeAreExactlyThese).
	asGivenShape = newShape(displayAsGiven, notShown)
)

// notShown is what a refusal of a value for its form shows of it: its length only (ADR-0031 §1).
func notShown(raw string) string { return logging.NotShown(raw) }

// displayAsGiven is raw as given, quoted when it holds a character that is not printable
// (logging.AsGiven).
func displayAsGiven(raw string) string { return logging.AsGiven(raw) }

// displayURLList shows each entry of a comma-separated list that is a URL as logging.MarkedURL does,
// and any other entry as displayAsGiven does.
func displayURLList(raw string) string {
	entries := splitList(raw)
	for i, e := range entries {
		if strings.Contains(e, "://") {
			entries[i] = logging.MarkedURL(e)
		} else {
			entries[i] = displayAsGiven(e)
		}
	}
	return strings.Join(entries, ", ")
}

// displayCommand is a command line given as a JSON array of strings, shown by its program and the
// number of arguments left out. A value that is not such an array shows as Hidden.
func displayCommand(raw string) string {
	var argv []string
	if json.Unmarshal([]byte(raw), &argv) != nil || len(argv) == 0 {
		return logging.Hidden
	}
	program := displayAsGiven(argv[0])
	switch n := len(argv) - 1; n {
	case 0:
		return program
	case 1:
		return program + " (1 argument not shown)"
	default:
		return fmt.Sprintf("%s (%d arguments not shown)", program, n)
	}
}
