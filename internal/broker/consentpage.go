package broker

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// consentView is what the consent page shows (ADR-0010 §4).
type consentView struct {
	Client      string
	Trust       string
	ReturnsTo   string // the redirect host, or "an app on this computer"
	Loopback    bool
	PublishedBy string // the CIMD host, for clients identified by a metadata document
	OtherSite   bool   // the redirect host is not part of PublishedBy's registrable domain
	Upstream    string
	IdP         string
	Operator    string
	ScopeText   string
	Raw         []string // the raw scope strings, behind a disclosure
	Lifetime    string
	Remembered  string // how long the answer will be remembered, when it will be (ADR-0010 §3)
	Flow        string
	Notice      string
	RequestID   string
	Stylesheet  string
	ContinueURL string
}

func (b *Broker) renderConsent(w http.ResponseWriter, r *http.Request, status int, client registration.Client, l login, sealed, notice string) {
	v := consentView{Client: displayName(client.Name(), client.ID()), Trust: trustLabel(client.Trust()), Upstream: b.upstreamName(),
		IdP: b.cfg.IdPLabel, Operator: b.cfg.OperatorName, ScopeText: b.scopeText(), Lifetime: lifetimeText(l.Scopes, client.AllowsRefresh()),
		Flow: sealed, Notice: notice, RequestID: logging.RequestID(r.Context()), Stylesheet: StylesheetPath, ContinueURL: "/consent"}
	if b.remembers(client) {
		v.Remembered = fmt.Sprintf("%d days", int(ConsentLifetime/(24*time.Hour)))
	}
	v.ReturnsTo, v.Loopback = returnsTo(l.RedirectURI)
	if p, ok := client.(metadataPublisher); ok {
		v.PublishedBy = showHost(p.MetadataHost())
		v.OtherSite = !v.Loopback && otherSite(p.MetadataHost(), l.RedirectURI)
	}
	v.Raw = requestedScopes(l.Scopes, b.cfg.IdPScopes)
	pageHeaders(w)
	w.WriteHeader(status)
	_ = consentTemplate.Execute(w, v)
}

// lifetimeText is how long the access may last: the grant's lifetime with offline_access (refresh
// tokens) for a client allowed to refresh, otherwise one access token's (ADR-0006 §5, ADR-0010 §4).
func lifetimeText(scopes []string, allowsRefresh bool) string {
	if allowsRefresh && slices.Contains(scopes, "offline_access") {
		return fmt.Sprintf("up to %d days", int(GrantLifetime/(24*time.Hour)))
	}
	return "up to 1 hour" // AccessLifetime; a test keeps the two in step
}

// upstreamName is the operator's name for the upstream, or the public host when it is unset or
// cleans down to nothing (only invisible characters).
func (b *Broker) upstreamName() string {
	return displayName(b.cfg.UpstreamName, b.cfg.Resource.Host)
}

func (b *Broker) scopeText() string {
	if b.cfg.ScopeText != "" {
		return b.cfg.ScopeText
	}
	return "Use " + b.upstreamName() + " as you, with everything you can do there."
}

// displayName strips control and format characters (bidi overrides among them) and cuts the name to
// 80 characters; an empty result falls back.
func displayName(name, fallback string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, name)
	clean = strings.Join(strings.Fields(clean), " ")
	if rs := []rune(clean); len(rs) > maxNameRunes {
		clean = string(rs[:maxNameRunes-1]) + "…"
	}
	if clean == "" {
		return fallback
	}
	return clean
}

func trustLabel(t registration.TrustLevel) string {
	switch t {
	case registration.Verified:
		return "Trusted by your operator"
	case registration.Domain:
		return "Identified by its web address"
	default:
		return "Not verified"
	}
}

// requestedScopes lists the client's scopes, then the IdP's, each once.
func requestedScopes(client []string, idpScopes string) []string {
	var out []string
	for _, s := range append(append([]string{}, client...), strings.Fields(idpScopes)...) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// returnsTo names where the browser goes after sign-in. Redirect URIs are validated (ADR-0009):
// https, or http on a loopback address. A host that is not plain ASCII is shown as written (minus
// invisible characters) with the ASCII name the browser will really use beside it (ADR-0010 §4),
// so look-alikes, full-width dots and zero-width joiners show their real spelling.
func returnsTo(redirect string) (string, bool) {
	u, err := url.Parse(redirect)
	if err != nil {
		return redirect, false
	}
	if u.Scheme == "http" {
		return "an app on this computer", true
	}
	return showHost(u.Hostname()), false
}

// showHost names a host as the user reads it: a host that is not plain ASCII is shown as written
// (minus invisible characters) with the ASCII name the browser will really use beside it, and an
// xn-- name with its Unicode spelling beside it (ADR-0010 §4).
func showHost(host string) string {
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		if ascii, err = idna.Punycode.ToASCII(host); err != nil {
			return displayName(host, "?")
		}
	}
	// "xn--" decodes to an empty label: there is no real host to name.
	if strings.Contains("."+ascii+".", "..") && !strings.Contains("."+host+".", "..") {
		return displayName(host, "?")
	}
	if ascii == strings.ToLower(host) {
		if uni, err := idna.Lookup.ToUnicode(ascii); err == nil && uni != ascii {
			return uni + " (" + ascii + ")"
		}
		return host
	}
	if shown := displayName(host, "?"); shown != ascii {
		return shown + " (" + ascii + ")"
	}
	return ascii
}

// metadataPublisher is a client identified by a Client ID Metadata Document.
type metadataPublisher interface{ MetadataHost() string }

// otherSite reports whether an https redirect leaves the CIMD host's registrable domain (eTLD+1,
// public suffix list), so app.example.com returning to auth.example.com is not flagged but
// claude.ai returning to evil.example is (ADR-0010 §4, amended). IP addresses and hosts without a
// registrable domain (a public suffix) are compared exactly.
func otherSite(cimdHost, redirect string) bool {
	u, err := url.Parse(redirect)
	if err != nil {
		return true
	}
	return site(cimdHost) != site(u.Hostname())
}

func site(host string) string {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return host // the public suffix list's default rule would make 203.0.113.7 "113.7"
	}
	if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return s
	}
	return host
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Allow {{.Client}} to use {{.Upstream}}?</title><link rel="stylesheet" href="{{.Stylesheet}}"></head>
<body><main>
<h1><span class="name">{{.Client}}</span> wants to use <span class="name">{{.Upstream}}</span> as you</h1>
{{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}
<dl>
<dt>App</dt><dd>{{.Client}} <span class="trust">({{.Trust}})</span></dd>
{{if .PublishedBy}}<dt>Published by</dt><dd>{{.PublishedBy}}</dd>{{end}}
<dt>Returns to</dt><dd>{{.ReturnsTo}}</dd>
<dt>It will be able to</dt><dd>{{.ScopeText}}</dd>
<dt>For</dt><dd>{{.Lifetime}}, unless access is revoked</dd>
{{if .Remembered}}<dt>Remembered</dt><dd>We'll remember your choice for this app for {{.Remembered}}. Your operator can revoke it.</dd>{{end}}
</dl>
{{if .OtherSite}}<p class="warning"><strong>This app returns to {{.ReturnsTo}}, which is not part of {{.PublishedBy}}.</strong> Only allow this if you expected that.</p>{{end}}
{{if .Loopback}}<p class="warning"><strong>Only allow this if you just started connecting from an app on this computer.</strong> Any app on this computer could have opened this page.</p>{{end}}
<details><summary>Technical details</summary><p>Requested permissions:</p><ul>{{range .Raw}}<li><code>{{.}}</code></li>{{end}}</ul></details>
<form method="post" action="{{.ContinueURL}}">
<input type="hidden" name="flow" value="{{.Flow}}">
<div class="actions"><button type="submit" name="action" value="deny">Deny</button><button type="submit" name="action" value="allow">Allow</button></div>
</form>
<p class="next">If you allow, you'll sign in with {{.IdP}} next.</p>
<footer>{{if .Operator}}Run by {{.Operator}}. {{end}}Reference: <code>{{.RequestID}}</code></footer>
</main></body></html>
`))
