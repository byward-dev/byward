package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/registration"
)

// Consent (ADR-0010). /authorize validates the request and shows the consent page; the page posts
// to /consent, which checks the request came from that page in this browser, then either sends the
// user to the IdP (Allow) or back to the client with access_denied (Deny).
//
// v0.1 asks every client every time. Remembering consent for static and verified clients
// (ADR-0010 §2-3) needs a per-user registry in the store and comes later; asking is never weaker.

const (
	// FlowLifetime is how long a consent page can be answered (ADR-0010 §5).
	FlowLifetime = 10 * time.Minute
	// ConsentDelay is how long Allow is refused after the page was shown (ADR-0010 §7): a click
	// that lands on Allow before the user could read the page (double-clickjacking) does nothing.
	ConsentDelay = time.Second
	maxNameRunes = 80
)

// flow is the sealed consent flow, carried in the page's form. It already holds the IdP login
// (state, nonce, verifier), so a repeated Allow sends the browser to the identical IdP request.
type flow struct {
	ID      string `json:"id"`
	Binding string `json:"b"` // sha256 of the binding cookie
	Shown   int64  `json:"t"` // unix milliseconds
	Login   login  `json:"l"`
}

// bindingCookie is the per-browser cookie a flow is bound to. Its name carries the instance ID, so
// two proxies on one host never read each other's cookie.
func (b *Broker) bindingCookie() string {
	sum := sha256.Sum256([]byte(b.cfg.Issuer))
	name := "mcpap_consent_" + hex.EncodeToString(sum[:4])
	if b.cfg.SecureCookies {
		return "__Host-" + name
	}
	return name
}

func bindingHash(v string) string {
	sum := sha256.Sum256([]byte("mcp-authproxy consent binding\x00" + v))
	return hex.EncodeToString(sum[:])
}

// showConsent renders the consent page for a validated authorization request.
func (b *Broker) showConsent(w http.ResponseWriter, r *http.Request, client registration.Client, l login) {
	binding := ""
	if c, err := r.Cookie(b.bindingCookie()); err == nil && len(c.Value) == 32 && strings.Trim(c.Value, "0123456789abcdef") == "" {
		binding = c.Value
	} else {
		binding = randomID()
	}
	now := b.cfg.Now()
	f := flow{ID: randomID(), Binding: bindingHash(binding), Shown: now.UnixMilli(), Login: l}
	plain, _ := json.Marshal(f)
	sealed, err := b.cfg.ConsentBox.Seal(plain, now.Add(FlowLifetime))
	if err != nil {
		b.serverError(w, r, err)
		return
	}
	//nolint:gosec // G124: Secure is false only in development mode on loopback http (ADR-0010 §10)
	http.SetCookie(w, &http.Cookie{Name: b.bindingCookie(), Value: binding, Path: "/", MaxAge: int(FlowLifetime.Seconds()),
		HttpOnly: true, Secure: b.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
	b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.ConsentShown, Outcome: audit.Success, ClientID: client.ID(),
		ClientTrust: string(client.Trust())})
	b.renderConsent(w, r, http.StatusOK, client, l, sealed, "")
}

// consent handles the page's answer.
func (b *Broker) consent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, sealed, allow, ok := b.readAnswer(w, r)
	if !ok {
		return
	}
	l := f.Login
	// The client and its redirect URI are checked again: the operator may have removed either.
	client, err := b.cfg.Clients.Client(ctx, l.ClientID)
	switch {
	case errors.Is(err, registration.ErrUnknownClient):
		b.page(w, r, http.StatusBadRequest, "This app is not registered with the proxy.", "Ask your operator to register the app, or check its client ID.")
		return
	case err != nil:
		b.serverError(w, r, err)
		return
	}
	if err := client.RedirectAllowed(l.RedirectURI); err != nil {
		b.page(w, r, http.StatusBadRequest, "This app asked to return to an address the proxy does not allow.", err.Error())
		return
	}
	now := b.cfg.Now()
	prev, repeat := b.answers.prior(f.ID, now)
	if repeat && prev != allow {
		b.page(w, r, http.StatusConflict, "You already answered this request.", "Start again from your app if you want to change your answer.")
		return
	}
	if allow && now.Sub(time.UnixMilli(f.Shown)) < ConsentDelay {
		b.renderConsent(w, r, http.StatusOK, client, l, sealed, "Take a moment to check the details, then choose again.")
		return
	}
	recorded, evicted := b.answers.record(f.ID, allow, now, time.UnixMilli(f.Shown).Add(FlowLifetime))
	if evicted {
		b.cfg.Log.WarnContext(ctx, "consent answer table full; forgot the most recently answered flow", "request_id", logging.RequestID(ctx))
	}
	if !recorded {
		b.page(w, r, http.StatusConflict, "You already answered this request.", "Start again from your app if you want to change your answer.")
		return
	}
	// One record per decision: a repeated answer (a double click) repeats the response only. The
	// sender is not signed in yet, so the records are limited per source (ADR-0021 §5).
	ev := audit.Event{ClientID: client.ID(), ClientTrust: string(client.Trust())}
	if !allow {
		ev.Name, ev.Outcome, ev.Reason = audit.ConsentDenied, audit.Failure, "the user denied the request"
		if !repeat {
			b.cfg.Audit.RecordUnauthenticated(r, ev)
		}
		b.redirectError(w, r, l.RedirectURI, l.State, "access_denied", "the user denied the request")
		return
	}
	ev.Name, ev.Outcome = audit.ConsentGranted, audit.Success
	if !repeat {
		b.cfg.Audit.RecordUnauthenticated(r, ev)
	}
	// The IdP state is stored only now, after Allow (ADR-0010 §5).
	b.startLogin(w, r, l, now)
}

// readAnswer checks that the answer is genuine: a POST from our own page (CSRF), a known action,
// an intact unexpired flow, and the browser the flow was shown in. Otherwise it writes the error
// page and returns ok false.
func (b *Broker) readAnswer(w http.ResponseWriter, r *http.Request) (f flow, sealed string, allow, ok bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return f, "", false, false
	}
	if !b.fromConsentPage(r) {
		b.page(w, r, http.StatusForbidden, "This answer did not come from the proxy's consent page.", "Start again from your app.")
		return f, "", false, false
	}
	unreadable := func() {
		b.page(w, r, http.StatusBadRequest, "This answer could not be read.", "Start again from your app.")
	}
	if err := r.ParseForm(); err != nil {
		unreadable()
		return f, "", false, false
	}
	switch r.PostForm.Get("action") {
	case "allow":
		allow = true
	case "deny":
	default:
		unreadable()
		return f, "", false, false
	}
	sealed = r.PostForm.Get("flow")
	plain, err := b.cfg.ConsentBox.Open(sealed)
	if err != nil || json.Unmarshal(plain, &f) != nil {
		b.page(w, r, http.StatusBadRequest, "This consent page has expired.", "Start again from your app.")
		return f, "", false, false
	}
	c, err := r.Cookie(b.bindingCookie())
	if err != nil || subtle.ConstantTimeCompare([]byte(bindingHash(c.Value)), []byte(f.Binding)) != 1 {
		b.page(w, r, http.StatusForbidden, "This consent page was opened in another browser.", "Start again from your app, in the browser it opens.")
		return f, "", false, false
	}
	return f, sealed, allow, true
}

// fromConsentPage is the CSRF check (ADR-0010 §5): exactly one Origin, our own, never derived from
// Host; Sec-Fetch-Site, when the browser sends it, agrees. A missing or "null" Origin fails.
func (b *Broker) fromConsentPage(r *http.Request) bool {
	if o := r.Header.Values("Origin"); len(o) != 1 || o[0] != b.cfg.Origin {
		return false
	}
	s := r.Header.Get("Sec-Fetch-Site")
	return s == "" || s == "same-origin"
}
