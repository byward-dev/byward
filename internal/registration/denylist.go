package registration

import (
	"fmt"
	"net/url"
	"strings"
)

// Denylist is the operator's list of refused CIMD clients and redirect hosts (ADR-0008 §9). It
// names a client by its CIMD URL, or every client that would return to a host, because a DCR
// client ID alone is re-registered around. Static clients are the operator's own and never
// checked. A nil *Denylist denies nothing.
type Denylist struct {
	urls, hosts map[string]bool
}

// NewDenylist parses entries: a CIMD client ID (an https URL) or a host name that redirect URIs
// must not return to. Both match exactly up to spelling: host case, a trailing dot, and for a
// URL the default port and percent-encoding in the path.
func NewDenylist(entries []string) (*Denylist, error) {
	d := &Denylist{urls: map[string]bool{}, hosts: map[string]bool{}}
	for _, e := range entries {
		switch {
		case IsCIMDURL(e):
			if err := ValidateCIMDURL(e); err != nil {
				return nil, fmt.Errorf("%q: %v", e, err)
			}
			d.urls[canonicalCIMD(e)] = true
		case e != "" && !strings.ContainsAny(e, "/:@*? ") && strings.Contains(e, "."):
			d.hosts[canonicalHost(e)] = true
		default:
			return nil, fmt.Errorf("%q is neither a CIMD client ID (https URL) nor a host name", e)
		}
	}
	return d, nil
}

// DeniesClient reports whether a CIMD client ID is on the list.
func (d *Denylist) DeniesClient(id string) bool { return d != nil && d.urls[canonicalCIMD(id)] }

// DeniesRedirect reports whether a redirect URI returns to a denied host.
func (d *Denylist) DeniesRedirect(redirectURI string) bool {
	if d == nil || len(d.hosts) == 0 {
		return false
	}
	u, err := url.Parse(redirectURI)
	return err == nil && d.hosts[canonicalHost(u.Hostname())]
}

// canonicalHost folds the spellings of one host: case and a trailing dot (app.example. is the
// same host as app.example).
func canonicalHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

// canonicalCIMD folds the spellings of one CIMD URL that fetch the same document: host case, a
// trailing dot, the default port and percent-encoding in the path. A denylist may match more
// than one spelling, never fewer.
func canonicalCIMD(id string) string {
	u, err := url.Parse(id)
	if err != nil {
		return id
	}
	return "https://" + canonicalHost(u.Hostname()) + u.Path
}
