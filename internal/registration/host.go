package registration

import (
	"strings"

	"golang.org/x/net/idna"
)

// BrowserHost is host as a browser goes to it, its one owner (the denylist matches by it and the
// consent page names it): the ASCII
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
// or "--", which browsers map).
var browserIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
	idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(false))
