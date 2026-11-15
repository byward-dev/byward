package broker

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every broker cookie is written by setCookie, so ADR-0010 §10's attributes are pinned here for
// both modes, for a cookie set and one deleted.
func TestCookiePolicy(t *testing.T) {
	cases := []struct {
		name     string
		secure   bool // Secure, and the __Host- prefix
		value    string
		maxAge   int // -1 deletes
		wantName string
	}{
		{"secure set", true, "v", 600, "__Host-byw_x"},
		{"secure delete", true, "", -1, "__Host-byw_x"},
		{"loopback http set", false, "v", 600, "byw_x"},
		{"loopback http delete", false, "", -1, "byw_x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &Broker{cfg: Config{SecureCookies: c.secure}}
			w := httptest.NewRecorder()
			b.setCookie(w, b.hostPrefixed("byw_x"), c.value, c.maxAge)
			got := w.Result().Cookies()
			if len(got) != 1 {
				t.Fatalf("cookies = %v, want one", got)
			}
			k := got[0]
			if k.Name != c.wantName || k.Value != c.value || k.Path != "/" || k.Domain != "" || !k.HttpOnly || k.Secure != c.secure ||
				k.SameSite != http.SameSiteLaxMode || k.MaxAge != c.maxAge {
				t.Fatalf("cookie %+v: want %s, Path=/, no Domain, HttpOnly, Secure=%v, SameSite=Lax, MaxAge=%d", k, c.wantName, c.secure, c.maxAge)
			}
		})
	}
}
