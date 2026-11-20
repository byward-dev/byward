package host

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// BrowserName is a host name as a browser goes to it, the one owner of that name form (the denylist
// matches by it; the consent page names it and compares sites by it, through BrowserNameOK); an IP
// address's browser form is Canonical's. It gives the ASCII name, folding case, a
// trailing dot (app.example. is app.example), full-width letters and full stops, and an
// internationalized name, which becomes its xn-- labels; so a Unicode spelling of a host compares
// equal to its xn-- form. A host the browser refuses (a joiner out of context, a label mixing
// directions, invalid punycode) is the mapping it got that far, so a denylist entry still matches it:
// more spellings, never fewer.
func BrowserName(host string) string { return Fold(browserIDNA, host) }

// BrowserNameOK is BrowserName, and whether a browser goes to that host at all: false when the browser
// refuses the host (including a name that is, or maps to, a forbidden domain code point: ＠ maps to @),
// or when no DNS name can be it (empty, invisible characters only, an empty label, as an "xn--" label
// decodes to). Where it is false, BrowserName is only the mapping it got that far,
// so the consent page must not name it as the destination nor compare sites by it. An IPv6 literal
// (without its brackets) has no domain to map and is a host the browser goes to.
func BrowserNameOK(host string) (string, bool) {
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		return BrowserName(host), true
	}
	ascii, err := browserIDNA.ToASCII(host)
	if endsInFullStop(host) { // only the host's own trailing dot, not one an empty last label left
		ascii = strings.TrimSuffix(ascii, ".")
	}
	return BrowserName(host), err == nil && ascii != "" && !strings.Contains("."+ascii+".", "..") &&
		!strings.ContainsFunc(ascii, forbiddenDomainCodePoint) && !decodesToXNLabel(ascii)
}

// decodesToXNLabel reports whether a label of ascii still begins with "xn--" once decoded
// (xn--xn--abc-t2a is xn--abcü). UTS #46 refuses such a label since revision 31 (Unicode 15.1),
// validity criterion 4, when CheckHyphens is off, as it is in browsers; x/net/idna does not apply
// that criterion.
func decodesToXNLabel(ascii string) bool {
	uni, err := browserIDNA.ToUnicode(ascii)
	if err != nil {
		return false
	}
	for label := range strings.SplitSeq(uni, ".") {
		if strings.HasPrefix(label, "xn--") {
			return true
		}
	}
	return false
}

// forbiddenDomainCodePoint reports whether r is a forbidden domain code point, which fails a host in
// the WHATWG URL Standard once its domain is ASCII: a C0 control or space, DEL, or one of
// # % / : < > ? @ [ \ ] ^ |. UTS #46 without the STD3
// rules maps full-width and compatibility forms to these (＠ to @, ℀ to a/c) and reports no error.
func forbiddenDomainCodePoint(r rune) bool {
	return r <= ' ' || r == 0x7f || strings.ContainsRune("#%/:<>?@[\\]^|", r)
}

// BrowserUnicode is the Unicode spelling of a name BrowserNameOK accepted, its xn-- labels decoded
// as a browser decodes them (an "_" allowed, as the STD3 rules of idna.Lookup do not); the name as
// given when the decoding reports an error.
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

// Fold maps h with p, keeping the mapping when p reports an error, and strips a trailing dot
// after the mapping (U+3002 and its kin become a dot). Only a host that maps to nothing at all keeps
// its own lower-cased spelling.
func Fold(p *idna.Profile, h string) string {
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
var browserIDNA = Profile(false)

// Profile is the browser's IDNA profile, with transitional mapping or without. The client denylist's
// transitional fold uses it too (ADR-0032 §1).
func Profile(transitional bool) *idna.Profile {
	return idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false),
		idna.BidiRule(), idna.CheckJoiners(true), idna.Transitional(transitional))
}
