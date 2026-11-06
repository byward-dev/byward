package logging

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientAddressTrustsForwardedForOnlyFromTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ffff::/48")}
	cases := []struct {
		name, peer string
		xff        []string
		want       string
	}{
		{"untrusted peer: header ignored", "203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"trusted peer, one hop", "10.1.2.3:4000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"rightmost untrusted hop wins over a spoofed leftmost", "10.1.2.3:4000", []string{"6.6.6.6, 198.51.100.1, 10.9.9.9"}, "198.51.100.1"},
		{"several header lines are one list", "10.1.2.3:4000", []string{"6.6.6.6", "198.51.100.1"}, "198.51.100.1"},
		{"trusted peer, no header", "10.1.2.3:4000", nil, "10.1.2.3"},
		{"a broken chain stops at the last trusted hop", "10.1.2.3:4000", []string{"198.51.100.1, garbage, 10.9.9.9"}, "10.9.9.9"},
		{"IPv6 proxy", "[2001:db8:ffff::1]:4000", []string{"2001:db8:1::5"}, "2001:db8:1::5"},
		{"mapped IPv4 is unmapped", "10.1.2.3:4000", []string{"::ffff:198.51.100.1"}, "198.51.100.1"},
		{"all hops trusted: the leftmost", "10.1.2.3:4000", []string{"10.5.5.5, 10.6.6.6"}, "10.5.5.5"},
		{"an entry with a port (Azure Application Gateway)", "10.1.2.3:4000", []string{"198.51.100.1:43210"}, "198.51.100.1"},
		{"a bracketed IPv6 entry with a port", "10.1.2.3:4000", []string{"[2001:db8:1::5]:443"}, "2001:db8:1::5"},
		{"a bracketed IPv6 entry", "10.1.2.3:4000", []string{"[2001:db8:1::5]"}, "2001:db8:1::5"},
		{"an empty entry breaks the chain", "10.1.2.3:4000", []string{"198.51.100.1,, 10.9.9.9"}, "10.9.9.9"},
		{"a zone is dropped", "10.1.2.3:4000", []string{"fe80::1%eth0"}, "fe80::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got string
			h := ClientAddress(trusted, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = RemoteIP(r) }))
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.peer
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if got != c.want {
				t.Fatalf("client address = %q, want %q", got, c.want)
			}
		})
	}
}

func TestWithoutTrustedProxiesForwardedForIsIgnored(t *testing.T) {
	var got string
	h := ClientAddress(nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = RemoteIP(r) }))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "127.0.0.1" {
		t.Fatalf("client address = %q, want the peer 127.0.0.1 (no trusted proxies by default)", got)
	}
}

func TestRemoteIPOutsideClientAddressIsThePeer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.7:51234"
	if got := RemoteIP(r); got != "192.0.2.7" {
		t.Fatalf("RemoteIP = %q, want 192.0.2.7", got)
	}
}
