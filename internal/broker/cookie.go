package broker

import "net/http"

// The broker's cookies (login, consent binding, consent hint) follow one policy (ADR-0010 §10):
// __Host- prefixed, Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain, except in development
// mode on loopback http, where SecureCookies is false and the prefix and Secure are dropped.

// hostPrefixed is the cookie name a browser stores: name with the __Host- prefix when cookies are
// Secure.
func (b *Broker) hostPrefixed(name string) string {
	if b.cfg.SecureCookies {
		return "__Host-" + name
	}
	return name
}

// setCookie writes the cookie name (already hostPrefixed) with the broker's attributes; a negative
// maxAge deletes it, and a browser deletes only a cookie whose Secure and Path match.
func (b *Broker) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	//nolint:gosec // G124: Secure is false only in development mode on loopback http (ADR-0010 §10)
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: b.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
}
