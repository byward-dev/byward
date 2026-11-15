package registration

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// Denylist is the operator's list of refused CIMD clients and redirect hosts (ADR-0008 §9). It
// names a client by its CIMD URL, or every client that would return to a host, because a DCR
// client ID alone is re-registered around. Static clients are the operator's own and never
// checked. A nil *Denylist denies nothing.
type Denylist struct {
	urls, hosts map[string]bool
}

// NewDenylist parses entries: a CIMD client ID (an https URL) or a host name that redirect URIs
// must not return to. Both match exactly up to spelling: the host's spelling (BrowserHost: case, a
// trailing dot, a full-width or internationalized name by its ASCII form), and for a URL the default
// port and percent-encoding in the path. A redirect host also matches by its transitional fold
// (DeniesRedirect).
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
			d.hosts[BrowserHost(e)] = true
		default:
			return nil, fmt.Errorf("%q is neither a CIMD client ID (https URL) nor a host name", e)
		}
	}
	return d, nil
}

// DeniesClient reports whether a CIMD client ID is on the list. Any other client ID, such as a
// static or DCR one, is never denied by ID, even when it looks like a URL.
func (d *Denylist) DeniesClient(id string) bool {
	return d != nil && IsCIMDURL(id) && d.urls[canonicalCIMD(id)]
}

// DeniesRedirect reports whether a redirect URI returns to a denied host. The host is also folded
// as an older or transitional IDNA implementation folds it (the deviation characters: ß and ẞ as ss,
// ς as σ, joiners dropped), since a browser with one goes there: either fold naming a denied host
// denies it.
func (d *Denylist) DeniesRedirect(redirectURI string) bool {
	if d == nil || len(d.hosts) == 0 {
		return false
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return d.hosts[BrowserHost(h)] || d.hosts[foldHost(transitionalIDNA, h)]
}

// transitionalIDNA is browserIDNA with transitional mapping, as browsers with IDNA tables before
// Unicode 15.1 map ẞ and as transitional ones map ß: the redirect host's second fold.
var transitionalIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
	idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(true))

// canonicalCIMD folds the spellings of one CIMD URL that fetch the same document: the host's
// spelling (BrowserHost), the default port and percent-encoding in the path. A denylist may match more
// than one spelling, never fewer.
func canonicalCIMD(id string) string {
	u, err := url.Parse(id)
	if err != nil {
		return id
	}
	return "https://" + BrowserHost(u.Hostname()) + u.Path
}
