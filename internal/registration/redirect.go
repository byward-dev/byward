package registration

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
)

// Redirect URI limits per registration (ADR-0009 §7).
const (
	MaxRedirectURIs   = 10
	MaxRedirectURILen = 512
)

// Redirect rejection reasons, for the mismatch metric (ADR-0009 §8).
const (
	ReasonNotRegistered = "not_registered"
	ReasonMalformed     = "malformed"
	ReasonScheme        = "scheme"
	ReasonFragment      = "fragment"
	ReasonUserinfo      = "userinfo"
	ReasonWildcard      = "wildcard"
	ReasonTooLong       = "too_long"
)

// RedirectError explains a rejected redirect URI. Error() is for the error page ("registered X,
// sent Y"); LogValue drops queries, which logs must never record (ADR-0009 §8).
type RedirectError struct {
	Reason     string
	Registered []string
	Sent       string
}

func (e *RedirectError) Error() string {
	if e.Reason == ReasonNotRegistered {
		return fmt.Sprintf("redirect URI not registered: registered %s, sent %s", strings.Join(e.Registered, ", "), e.Sent)
	}
	return fmt.Sprintf("redirect URI %s rejected: %s", e.Sent, reasonText[e.Reason])
}

// LogValue reports the reason and the sent URI's scheme, host and path only.
func (e *RedirectError) LogValue() slog.Value {
	return slog.GroupValue(slog.String("reason", e.Reason), slog.String("sent", withoutQuery(e.Sent)))
}

var reasonText = map[string]string{
	ReasonMalformed: "not an absolute URI",
	ReasonScheme:    "must be https, or http on a loopback host (127.0.0.1, [::1], localhost)",
	ReasonFragment:  "must not contain a fragment",
	ReasonUserinfo:  "must not contain user information",
	ReasonWildcard:  "must not contain wildcards",
	ReasonTooLong:   fmt.Sprintf("longer than %d characters", MaxRedirectURILen),
}

func withoutQuery(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// loopbackHosts are the hosts on which http and any port are allowed (ADR-0009 §2).
var loopbackHosts = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// ValidateRedirect checks one redirect URI against ADR-0009 §1-3 and §7.
func ValidateRedirect(raw string) error {
	_, err := parseRedirect(raw)
	return err
}

func parseRedirect(raw string) (*url.URL, error) {
	reject := func(reason string) (*url.URL, error) { return nil, &RedirectError{Reason: reason, Sent: raw} }
	if len(raw) > MaxRedirectURILen {
		return reject(ReasonTooLong)
	}
	if strings.Contains(raw, "#") {
		return reject(ReasonFragment)
	}
	if strings.Contains(raw, "*") {
		return reject(ReasonWildcard)
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return reject(ReasonMalformed)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || !u.IsAbs() {
		return reject(ReasonMalformed)
	}
	if u.User != nil {
		return reject(ReasonUserinfo)
	}
	// The scheme must be written in lower case: matching is exact, and url.Parse would otherwise
	// fold "HTTP" into "http".
	if !strings.HasPrefix(raw, u.Scheme+"://") {
		return reject(ReasonScheme)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHosts[u.Hostname()] {
			return reject(ReasonScheme)
		}
	default:
		return reject(ReasonScheme)
	}
	return u, nil
}

// ValidateRedirects checks a registration's redirect URIs: 1 to MaxRedirectURIs entries, each valid
// and unique (ADR-0009 §1-3, §7).
func ValidateRedirects(uris []string) error {
	if len(uris) == 0 || len(uris) > MaxRedirectURIs {
		return fmt.Errorf("redirect_uris: between 1 and %d required", MaxRedirectURIs)
	}
	for i, u := range uris {
		if err := ValidateRedirect(u); err != nil {
			return fmt.Errorf("redirect_uris[%d]: %w", i, err)
		}
		if slices.Contains(uris[:i], u) {
			return fmt.Errorf("redirect_uris[%d]: duplicate", i)
		}
	}
	return nil
}

// afterAuthority is the raw path and query of an absolute URI, exactly as written, so differently
// escaped paths never compare equal.
func afterAuthority(raw string) string {
	rest := raw[strings.Index(raw, "://")+3:]
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		return rest[i:]
	}
	return ""
}

// MatchRedirect applies ADR-0009 to a redirect URI sent at /authorize or /token: HTTPS must equal
// a registered URI exactly; a loopback URI matches a registered one with the same scheme, host
// literal, path and query, on any port.
func MatchRedirect(registered []string, sent string) error {
	u, err := parseRedirect(sent)
	if err != nil {
		var re *RedirectError
		if errors.As(err, &re) {
			re.Registered = registered
		}
		return err
	}
	for _, r := range registered {
		if r == sent {
			return nil
		}
		if u.Scheme != "http" {
			continue
		}
		ru, err := parseRedirect(r)
		if err != nil || ru.Scheme != "http" {
			continue
		}
		if ru.Hostname() == u.Hostname() && afterAuthority(r) == afterAuthority(sent) {
			return nil
		}
	}
	return &RedirectError{Reason: ReasonNotRegistered, Registered: registered, Sent: sent}
}
