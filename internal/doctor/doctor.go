// Package doctor is the operator's online check (ADR-0020 §7, ADR-0021 §11): a self-probe of the
// proxy's discovery as MCP clients do it (ADR-0013 §8), plus the checks of the IdP adapter, each
// result naming the fix.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Class groups checks for the exit code.
type Class string

// Check classes.
const (
	// ClassProxy is what MCP clients see of the proxy: discovery, the 401 challenge, Host.
	ClassProxy Class = "proxy"
	// ClassIdP is the IdP app and the proxy's credential at the IdP.
	ClassIdP Class = "idp"
)

// Status is a check's outcome. Only Fail changes the exit code.
type Status string

// Statuses.
const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	// Skip means the check could not run; Message says why and Fix how to check by hand.
	Skip Status = "skip"
)

// Result is one check.
type Result struct {
	Class   Class  `json:"class"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// Report is every check of one doctor run, in the order they ran.
type Report struct {
	Checks []Result `json:"checks"`
}

// Exit code bits, OR-ed when both classes fail (12). Configuration errors keep exit code 2 and
// stop doctor before any check runs; warnings and skips exit 0.
const (
	ExitProxy = 4
	ExitIdP   = 8
)

// ExitCode is 0, or the OR of the bits of every class with a failed check.
func (r Report) ExitCode() int {
	code := 0
	for _, c := range r.Checks {
		if c.Status != Fail {
			continue
		}
		switch c.Class {
		case ClassProxy:
			code |= ExitProxy
		case ClassIdP:
			code |= ExitIdP
		}
	}
	return code
}

// WriteText prints one line per check, then its fix indented below it.
func (r Report) WriteText(w io.Writer) {
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(w, "%-4s  %-5s  %s: %s\n", c.Status, c.Class, c.Name, c.Message)
		if c.Fix != "" {
			_, _ = fmt.Fprintf(w, "             fix: %s\n", c.Fix)
		}
	}
}

// WriteJSON prints the report as one JSON document.
func (r Report) WriteJSON(w io.Writer) error {
	if r.Checks == nil {
		r.Checks = []Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// secretWarnBefore is how early an expiring client secret is a warning (ADR-0012 §10).
const secretWarnBefore = 30 * 24 * time.Hour

// SecretExpiry checks the client secret's end date, which the operator states in setting (the IdP
// does not tell). A zero expires means it was not stated.
func SecretExpiry(setting string, expires, now time.Time) Result {
	r := Result{Class: ClassIdP, Name: "client secret expiry"}
	left := expires.Sub(now)
	switch {
	case expires.IsZero():
		r.Status, r.Message = Skip, "the expiry date is not configured"
		r.Fix = "set " + setting + " to the secret's end date, so doctor and the startup log warn before it expires"
	case left <= 0:
		r.Status, r.Message = Fail, "the client secret expired on "+expires.Format(time.DateOnly)+"; every sign-in and refresh fails"
		r.Fix = "create a new secret, restart the proxy with it, and update " + setting
	case left <= secretWarnBefore:
		r.Status, r.Message = Warn, fmt.Sprintf("the client secret expires on %s, in %d days", expires.Format(time.DateOnly), int(left.Hours()/24))
		r.Fix = "create a new secret before then, restart the proxy with it, and update " + setting
	default:
		r.Status, r.Message = Pass, "the client secret is valid until "+expires.Format(time.DateOnly)
	}
	return r
}
