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
// must not return to. Both match exactly up to spelling: the host's spelling (canonicalHost: case, a
// trailing dot, an internationalized or full-width name by its xn-- form), and for a URL the default
// port and percent-encoding in the path.
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

// DeniesClient reports whether a CIMD client ID is on the list. Any other client ID, such as a
// static or DCR one, is never denied by ID, even when it looks like a URL.
func (d *Denylist) DeniesClient(id string) bool {
	return d != nil && IsCIMDURL(id) && d.urls[canonicalCIMD(id)]
}

// DeniesRedirect reports whether a redirect URI returns to a denied host. The host is also folded
// as an older or transitional IDNA implementation folds it (ß and ẞ as ss), since a browser with one
// goes there: either fold naming a denied host denies it.
func (d *Denylist) DeniesRedirect(redirectURI string) bool {
	if d == nil || len(d.hosts) == 0 {
		return false
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return d.hosts[canonicalHost(h)] || d.hosts[foldHost(transitionalHost, h)]
}

// canonicalHost folds the spellings of one host into the ASCII name a browser really goes to: case,
// a trailing dot (app.example. is the same host as app.example), and an internationalized or
// full-width name, which becomes its xn-- form, so a Unicode spelling of a denied host is denied too.
// A host browserHost refuses (a joiner out of context, a label mixing directions, invalid punycode)
// is compared by the mapping it got that far, so it matches its own xn-- or lower-case form: more
// spellings, never fewer.
func canonicalHost(h string) string { return foldHost(browserHost, h) }

// foldHost maps h with p, keeping the mapping when p reports an error, and strips a trailing dot
// after the mapping (U+3002 and its kin become a dot). Only a host that maps to nothing at all keeps
// its own lower-cased spelling.
func foldHost(p *idna.Profile, h string) string {
	if ascii, _ := p.ToASCII(h); ascii != "" {
		h = ascii
	} else {
		h = strings.ToLower(h)
	}
	return strings.TrimSuffix(h, ".")
}

// browserHost is the WHATWG URL Standard's "domain to ASCII" with beStrict false, which browsers run
// on a URL's host: UTS #46 non-transitional mapping with the Bidi and joiner checks, and neither the
// STD3 rules nor the hyphen check, so a name with "_" or "--" maps as the browser maps it (idna.Lookup
// applies both and reports an error on such a name). transitionalHost is the same with transitional
// mapping, as browsers with IDNA tables before Unicode 15.1 map ẞ and as transitional ones map ß.
var (
	browserHost = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
		idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(false))
	transitionalHost = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
		idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(true))
)

// canonicalCIMD folds the spellings of one CIMD URL that fetch the same document: the host's
// spelling (canonicalHost), the default port and percent-encoding in the path. A denylist may match more
// than one spelling, never fewer.
func canonicalCIMD(id string) string {
	u, err := url.Parse(id)
	if err != nil {
		return id
	}
	return "https://" + canonicalHost(u.Hostname()) + u.Path
}
