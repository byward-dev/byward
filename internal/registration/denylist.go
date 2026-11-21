package registration

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/byward-dev/byward/internal/host"
)

// Denylist is the operator's list of refused CIMD clients and redirect hosts (ADR-0008 §9). It
// names a client by its CIMD URL, or every client that would return to a host, because a DCR
// client ID alone is re-registered around. Static clients are the operator's own and never
// checked. A nil *Denylist denies nothing.
type Denylist struct {
	urls, hosts map[string]bool
}

// NewDenylist parses entries: a CIMD client ID (an https URL) or a host name that redirect URIs
// must not return to. Both match exactly up to spelling: the host's spelling (host.BrowserName: case, a
// trailing dot, a full-width or internationalized name by its ASCII form), and for a URL the default
// port and percent-encoding in the path. A redirect host also matches by its transitional fold
// (DeniesRedirect).
// A refused entry is an *EntryError, which never holds the entry: config formats its refusal
// (ADR-0031 §1).
func NewDenylist(entries []string) (*Denylist, error) {
	d := &Denylist{urls: map[string]bool{}, hosts: map[string]bool{}}
	for i, e := range entries {
		switch {
		case IsCIMDURL(e):
			if err := ValidateCIMDURL(e); err != nil {
				reason := err.Error()
				if ce := (*cimdURLError)(nil); errors.As(err, &ce) {
					reason = "it is not a client ID metadata document URL: " + ce.Reason
				}
				return nil, &EntryError{Index: i, Reason: reason}
			}
			d.urls[canonicalCIMD(e)] = true
		case e != "" && !strings.ContainsAny(e, "/:@*? ") && strings.Contains(e, "."):
			d.hosts[host.BrowserName(e)] = true
		default:
			return nil, &EntryError{Index: i, Reason: "it is neither a CIMD client ID (https URL) nor a host name"}
		}
	}
	return d, nil
}

// EntryError is a refused denylist entry, by its index in the list and a fixed reason, a clause such as
// "it is not …": it never holds the entry, which can be a credential pasted in the wrong place.
type EntryError struct {
	Index  int
	Reason string
}

func (e *EntryError) Error() string { return fmt.Sprintf("entry %d: %s", e.Index+1, e.Reason) }

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
	return d.hosts[host.BrowserName(h)] || d.hosts[transitionalHost(h)]
}

// canonicalCIMD folds the spellings of one CIMD URL that fetch the same document: the host's
// spelling (host.BrowserName), the default port and percent-encoding in the path. A denylist may match more
// than one spelling, never fewer.
func canonicalCIMD(id string) string {
	u, err := url.Parse(id)
	if err != nil {
		return id
	}
	return "https://" + host.BrowserName(u.Hostname()) + u.Path
}
