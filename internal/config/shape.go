package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/byward-dev/byward/internal/logging"
)

// shape is the kind of value a setting holds, which decides how the value is shown (ADR-0031 §3):
// display gives an accepted value as the startup log and --print-config show it, and refused gives what
// a refusal of a value for its form will show of it once refusals go through the shape (#494).
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
// only from a file (Setting.Secret).
var (
	// secretShape is a secret: read only from a file and never shown.
	secretShape = newShape(func(string) string { return "<redacted>" }, notShown)
	// urlShape is a URL the proxy uses whole: shown by its scheme, host and path, with a marker for
	// each part left out, since a query can hold an API key (logging.MarkedURL, #458).
	urlShape = newShape(logging.MarkedURL, notShown)
	// urlListShape is a comma-separated list whose entries can be URLs: each URL entry is shown as
	// urlShape shows it, and any other entry as given.
	urlListShape = newShape(displayURLList, notShown)
	// commandShape is a command line as a JSON array: shown by its program and how many arguments
	// follow, since an argument can be a token (displayCommand).
	commandShape = newShape(displayCommand, notShown)
	// asGivenShape is any other value: shown as given. A setting gets it by a reviewed decision
	// (TestTheSettingsOfEachShapeAreExactlyThese).
	asGivenShape = newShape(func(raw string) string { return raw }, notShown)
)

// notShown is what a refusal of a value for its form will show of it (#494): its length only
// (ADR-0031 §1).
func notShown(raw string) string {
	if n := utf8.RuneCountInString(raw); n != 1 {
		return fmt.Sprintf("(%d characters, not shown)", n)
	}
	return "(1 character, not shown)"
}

// displayURLList shows each entry of a comma-separated list that is a URL as logging.MarkedURL does,
// and any other entry as given.
func displayURLList(raw string) string {
	entries := splitList(raw)
	for i, e := range entries {
		if strings.Contains(e, "://") {
			entries[i] = logging.MarkedURL(e)
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
	program := argv[0]
	if strings.ContainsFunc(program, func(r rune) bool { return !strconv.IsPrint(r) }) { // a newline would start a new line of output
		program = strconv.Quote(program)
	}
	switch n := len(argv) - 1; n {
	case 0:
		return program
	case 1:
		return program + " (1 argument not shown)"
	default:
		return fmt.Sprintf("%s (%d arguments not shown)", program, n)
	}
}
