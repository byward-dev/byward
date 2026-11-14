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

// warnBefore is how early an expiring credential or certificate is a warning (ADR-0012 §10).
const warnBefore = 30 * 24 * time.Hour

// Expiry is an end date as an expiry check sees it at a moment: Fail once it has passed, Warn within
// 30 days of it, else Pass. Date is the end date in UTC, and In says how soon it is ("in 3 days")
// in calendar days in UTC, so the two agree.
type Expiry struct {
	Status   Status
	Date, In string
}

// ExpiryAt is notAfter's Expiry at now. Each check words its own messages from it.
func ExpiryAt(notAfter, now time.Time) Expiry {
	e := Expiry{Status: Pass, Date: notAfter.UTC().Format(time.DateOnly), In: inDays(notAfter, now)}
	switch left := notAfter.Sub(now); {
	case left <= 0:
		e.Status = Fail
	case left <= warnBefore:
		e.Status = Warn
	}
	return e
}

// inDays says how soon notAfter is from now: under a day, or in calendar days in UTC, the zone its
// date is given in, so the count agrees with the date.
func inDays(notAfter, now time.Time) string {
	if notAfter.Sub(now) < 24*time.Hour {
		return "in less than a day"
	}
	midnight := func(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }
	if days := int(midnight(notAfter).Sub(midnight(now)) / (24 * time.Hour)); days != 1 {
		return fmt.Sprintf("in %d days", days)
	}
	return "in 1 day"
}

// SecretExpiry checks the client secret's end date, which the operator states in setting (the IdP
// does not tell). A zero expires means it was not stated.
func SecretExpiry(setting string, expires, now time.Time) Result {
	r := CheckClientSecretExpiry.NewResult()
	if expires.IsZero() {
		r.Status, r.Message = Skip, "the expiry date is not configured"
		r.Fix = "set " + setting + " to the secret's end date, so doctor and the startup log warn before it expires"
		return r
	}
	e := ExpiryAt(expires, now)
	switch r.Status = e.Status; e.Status {
	case Fail:
		r.Message = "the client secret expired on " + e.Date + "; every sign-in and refresh fails"
		r.Fix = "create a new secret, restart the proxy with it, and update " + setting
	case Warn:
		r.Message = "the client secret expires on " + e.Date + ", " + e.In
		r.Fix = "create a new secret before then, restart the proxy with it, and update " + setting
	default:
		r.Message = "the client secret is valid until " + e.Date
	}
	return r
}

// CertificateExpiry is the client certificate's lifetime check (ADR-0012 §5, §10), from its own
// end date: a warning within 30 days of it, a failure once it has passed. setting names the file.
func CertificateExpiry(setting string, notAfter, now time.Time) Result {
	r := CheckClientCertificateExpiry.NewResult()
	e := ExpiryAt(notAfter, now)
	switch r.Status = e.Status; e.Status {
	case Fail:
		r.Message = "the client certificate expired on " + e.Date + "; every sign-in and refresh fails"
		r.Fix = "make and upload a new certificate, then restart the proxy with it in " + setting + " (docs/how-to/entra-certificate.md)"
	case Warn:
		r.Message = "the client certificate expires on " + e.Date + ", " + e.In
		r.Fix = "make and upload a new certificate before then, and restart the proxy with it in " + setting + " (docs/how-to/entra-certificate.md)"
	default:
		r.Message = "the client certificate is valid until " + e.Date
	}
	return r
}
