package registration

import (
	"strings"

	"golang.org/x/net/idna"
)

// BrowserHost is host as a browser goes to it, its one owner (the denylist matches by it; the consent
// page names it and compares sites by it, through BrowserHostOK): the ASCII name, folding case, a
// trailing dot (app.example. is app.example), full-width letters and full stops, and an
// internationalized name, which becomes its xn-- labels; so a Unicode spelling of a host compares
// equal to its xn-- form. A host the browser refuses (a joiner out of context, a label mixing
// directions, invalid punycode) is the mapping it got that far, so a denylist entry still matches it:
// more spellings, never fewer.
func BrowserHost(host string) string { return foldHost(browserIDNA, host) }

// BrowserHostOK is BrowserHost, and whether a browser goes to that host at all: false when the browser
// refuses the host (including a name that is, or maps to, a forbidden domain code point: ＠ maps to @),
// or when no DNS name can be it (empty, invisible characters only, an empty label, as an "xn--" label
// decodes to). Where it is false, BrowserHost is only the mapping it got that far,
// so the consent page must not name it as the destination nor compare sites by it.
func BrowserHostOK(host string) (string, bool) {
	ascii, err := browserIDNA.ToASCII(host)
	if endsInFullStop(host) { // only the host's own trailing dot, not one an empty last label left
		ascii = strings.TrimSuffix(ascii, ".")
	}
	return BrowserHost(host), err == nil && ascii != "" && !strings.Contains("."+ascii+".", "..") &&
		!strings.ContainsFunc(ascii, forbiddenDomainCodePoint)
}

// forbiddenDomainCodePoint reports whether the WHATWG URL Standard fails a host whose domain to ASCII
// holds r: a C0 control or space, DEL, or one of # % / : < > ? @ [ \ ] ^ |. UTS #46 without the STD3
// rules maps full-width and compatibility forms to these (＠ to @, ℀ to a/c) and reports no error.
func forbiddenDomainCodePoint(r rune) bool {
	return r <= ' ' || r == 0x7f || strings.ContainsRune("#%/:<>?@[\\]^|", r)
}

// BrowserUnicode is the Unicode spelling of a name BrowserHostOK accepted, its xn-- labels decoded
// as a browser decodes them (an "_" allowed, as the STD3 rules of idna.Lookup do not); the name
// itself when nothing decodes.
func BrowserUnicode(ascii string) string {
	if uni, err := browserIDNA.ToUnicode(ascii); err == nil {
		return uni
	}
	return ascii
}

// endsInFullStop reports whether host ends in a full stop, as written: "." or one UTS #46 maps to it.
func endsInFullStop(host string) bool {
	return strings.HasSuffix(host, ".") || strings.HasSuffix(host, "\u3002") || strings.HasSuffix(host, "\uff0e") ||
		strings.HasSuffix(host, "\uff61")
}

// transitionalHost is host as a browser with older or transitional IDNA goes to it: ß and ẞ as ss, ς
// as σ, joiners dropped. The denylist folds a redirect host this way too.
func transitionalHost(host string) string { return foldHost(transitionalIDNA, host) }

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
	browserIDNA      = browserProfile(false)
	transitionalIDNA = browserProfile(true)
)

func browserProfile(transitional bool) *idna.Profile {
	return idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
		idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(transitional))
}
