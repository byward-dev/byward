package broker

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/registration"
	"golang.org/x/net/idna"
)

// consentView is what the consent page shows (ADR-0010 §4).
type consentView struct {
	Client      string
	Trust       string
	ReturnsTo   string // the redirect host, or "an app on this computer"
	Loopback    bool
	Upstream    string
	IdP         string
	Operator    string
	ScopeText   string
	Raw         []string // the raw scope strings, behind a disclosure
	Lifetime    string
	Flow        string
	Notice      string
	RequestID   string
	Stylesheet  string
	ContinueURL string
}

func (b *Broker) renderConsent(w http.ResponseWriter, r *http.Request, status int, client registration.Client, l login, sealed, notice string) {
	v := consentView{Client: displayName(client.Name(), client.ID()), Trust: trustLabel(client.Trust()), Upstream: b.upstreamName(),
		IdP: b.cfg.IdPLabel, Operator: b.cfg.OperatorName, ScopeText: b.scopeText(), Lifetime: lifetimeText(l.Scopes),
		Flow: sealed, Notice: notice, RequestID: logging.RequestID(r.Context()), Stylesheet: StylesheetPath, ContinueURL: "/consent"}
	v.ReturnsTo, v.Loopback = returnsTo(l.RedirectURI)
	v.Raw = requestedScopes(l.Scopes, b.cfg.IdPScopes)
	pageHeaders(w)
	w.WriteHeader(status)
	_ = consentTemplate.Execute(w, v)
}

// lifetimeText is how long the access may last: the grant's lifetime with offline_access (refresh
// tokens), otherwise one access token's (ADR-0006 §5, ADR-0010 §4).
func lifetimeText(scopes []string) string {
	if slices.Contains(scopes, "offline_access") {
		return fmt.Sprintf("up to %d days", int(GrantLifetime/(24*time.Hour)))
	}
	return fmt.Sprintf("up to %d hour", int(AccessLifetime/time.Hour))
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
	host := u.Hostname()
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		if ascii, err = idna.Punycode.ToASCII(host); err != nil {
			return displayName(host, "?"), false
		}
	}
	// "xn--" decodes to an empty label: there is no real host to name.
	if strings.Contains("."+ascii+".", "..") && !strings.Contains("."+host+".", "..") {
		return displayName(host, "?"), false
	}
	if ascii == strings.ToLower(host) {
		if uni, err := idna.Lookup.ToUnicode(ascii); err == nil && uni != ascii {
			return uni + " (" + ascii + ")", false
		}
		return host, false
	}
	if shown := displayName(host, "?"); shown != ascii {
		return shown + " (" + ascii + ")", false
	}
	return ascii, false
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Allow {{.Client}} to use {{.Upstream}}?</title><link rel="stylesheet" href="{{.Stylesheet}}"></head>
<body><main>
<h1><span class="name">{{.Client}}</span> wants to use <span class="name">{{.Upstream}}</span> as you</h1>
{{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}
<dl>
<dt>App</dt><dd>{{.Client}} <span class="trust">({{.Trust}})</span></dd>
<dt>Returns to</dt><dd>{{.ReturnsTo}}</dd>
<dt>It will be able to</dt><dd>{{.ScopeText}}</dd>
<dt>For</dt><dd>{{.Lifetime}}, unless access is revoked</dd>
</dl>
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
