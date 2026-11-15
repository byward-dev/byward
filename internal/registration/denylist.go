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

// BrowserHost is host as a browser goes to it, its one owner (also for the consent page): the ASCII
// name, folding case, a trailing dot (app.example. is app.example), full-width letters and full stops,
// and an internationalized name, which becomes its xn-- labels; so a Unicode spelling of a host
// compares equal to its xn-- form. A host the browser refuses (a joiner out of context, a label mixing
// directions, invalid punycode) is the mapping it got that far, so it still equals its own xn-- or
// lower-case form: more spellings, never fewer.
func BrowserHost(host string) string { return foldHost(browserIDNA, host) }

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

// browserIDNA is the WHATWG URL Standard's "domain to ASCII" with beStrict false, which browsers run
// on a URL's host: UTS #46 non-transitional mapping with the Bidi and joiner checks, and neither the
// STD3 rules nor the hyphen check (idna.Lookup applies both and reports an error on a name with "_"
// or "--", which browsers map). transitionalIDNA is the same with transitional mapping, as browsers
// with IDNA tables before Unicode 15.1 map ẞ and as transitional ones map ß.
var (
	browserIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
		idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(false))
	transitionalIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
		idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(true))
)

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
