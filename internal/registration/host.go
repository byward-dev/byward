package registration

import "github.com/byward-dev/byward/internal/host"

// transitionalHost is h as a browser with older or transitional IDNA goes to it: ß and ẞ as ss, ς
// as σ, joiners dropped. The denylist folds a redirect host this way too, besides the browser's own
// fold (host.BrowserName), so it matches more spellings on purpose (ADR-0032 §1).
func transitionalHost(h string) string { return host.Fold(transitionalIDNA, h) }

// transitionalIDNA is the browser's IDNA profile with transitional mapping, as browsers with IDNA
// tables before Unicode 15.1 map ẞ and as transitional ones map ß.
var transitionalIDNA = host.Profile(true)
