package origin

import (
	"fmt"
	"time"

	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/audit"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

func quiet() *audit.Log {
	return audit.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, time.Now)
}

// preflight is a browser's CORS preflight from origin for a POST, listing requestHeaders as
// Access-Control-Request-Headers lines.
func preflight(origin string, requestHeaders ...string) *http.Request {
	r := httptest.NewRequest("OPTIONS", "/mcp", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	for _, v := range requestHeaders {
		r.Header.Add("Access-Control-Request-Headers", v)
	}
	return r
}

func TestHostOutsideAllowlistGets421(t *testing.T) {
	h := Hosts(quiet(), []string{"mcp.example.com", "internal:8080"}, ok)
	cases := map[string]int{
		"mcp.example.com":     http.StatusNoContent,
		"MCP.Example.com":     http.StatusNoContent,
		"mcp.example.com:443": http.StatusNoContent,
		"internal:8080":       http.StatusNoContent,
		"internal":            http.StatusMisdirectedRequest,
		"evil.example":        http.StatusMisdirectedRequest,
		"mcp.example.com:444": http.StatusMisdirectedRequest,
		"":                    http.StatusMisdirectedRequest,
	}
	for host, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("host %q: got %d want %d", host, w.Code, want)
		}
	}
}

// matchesOnly checks that Hosts with listed alone passes every Host header in match and answers 421
// to every one in refuse.
func matchesOnly(t *testing.T, listed string, match, refuse []string) {
	t.Helper()
	h := Hosts(quiet(), []string{listed}, ok)
	code := func(host string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, host := range match {
		if c := code(host); c != http.StatusNoContent {
			t.Errorf("Host %q should match %q: got %d", host, listed, c)
		}
	}
	for _, host := range refuse {
		if c := code(host); c != http.StatusMisdirectedRequest {
			t.Errorf("Host %q should be refused against %q: got %d", host, listed, c)
		}
	}
}

// A Host header may leave out a default port (:443 or :80) or carry one, either way round from the
// listed entry, as browsers leave it out and a proxy behind a TLS-terminating load balancer may add
// :80; only one, once, so a doubled port is another host.
func TestOneDefaultPortIsIgnoredOnce(t *testing.T) {
	for _, tc := range []struct {
		listed        string
		match, refuse []string
	}{
		{"localhost", []string{"localhost", "localhost:443", "localhost:80"}, []string{"localhost:443:443", "localhost:80:443", "localhost:8080"}},
		{"localhost:443", []string{"localhost", "localhost:443", "localhost:80"}, []string{"localhost:8443"}},
		{"localhost:80", []string{"localhost", "localhost:443"}, []string{"localhost:80:80"}},
		{"[::1]", []string{"[::1]:443", "[::1]:80"}, []string{"[::1]:80:443", "[::1]:8080"}},
	} {
		t.Run(tc.listed, func(t *testing.T) {
			matchesOnly(t, tc.listed, tc.match, tc.refuse)
		})
	}
}

// A listed host matches a Host header in any spelling of the same address, as browsers and fetch
// send the canonical form and Go and Python clients send it as written (#447); both sides are
// compared canonical, whatever form the list holds. A name matches only itself, even one ending in a
// number or built from an address (DNS rebinding, invariant 17).
func TestAListedHostMatchesEverySpellingOfItsAddressAndNoOtherHost(t *testing.T) {
	for _, tc := range []struct {
		listed        string
		match, refuse []string
	}{
		{"[2001:DB8:0:0::1]", []string{"[2001:db8::1]", "[2001:DB8::1]", "[2001:db8:0:0:0:0:0:1]"}, []string{"[2001:db8::2]", "2001:db8::1.example"}},
		{"[::ffff:127.0.0.1]:8443", []string{"[::ffff:7f00:1]:8443", "[::FFFF:127.0.0.1]:8443"}, []string{"[::ffff:7f00:1]", "127.0.0.1:8443"}},
		{"127.0.0.1:8080", []string{"127.1:8080", "2130706433:8080", "0x7f.0.0.1:8080", "0177.0.0.1:8080"},
			[]string{"127.0.0.2:8080", "127.0.0.1:8081", "127.0.0.1.evil:8080", "127.0.0.1.5:8080", "127.0.0.1.0:8080", "[127.0.0.1]:8080"}}, // .0 passes the size check, so only the five-part limit refuses it
		{"0.0.0.0", []string{"0", "0x0.0"}, []string{"4294967296", "18446744073709551616", "0x10000000000000000"}}, // overflow never wraps to 0.0.0.0
		{"127.0.0.2", nil, []string{"127.1", "0x7f.0.0.1", "127.0.0.1"}},                                           // another address, however spelled
		{"mcp.10", []string{"MCP.10"}, []string{"mcp.0xa", "mcp.010", "0.0.0.10", "10.0.0.0"}},
	} {
		t.Run(tc.listed, func(t *testing.T) {
			matchesOnly(t, tc.listed, tc.match, tc.refuse)
		})
	}
}

func TestInternalListenerAcceptsAddressesAndListedNamesOnly(t *testing.T) {
	h := InternalHosts(quiet(), []string{"byward-metrics.monitoring.svc:8080"}, ok)
	cases := map[string]int{
		"127.0.0.1:9090":                     http.StatusNoContent,
		"10.244.1.17:9090":                   http.StatusNoContent, // kubelet and Prometheus use the pod IP
		"[::1]:9090":                         http.StatusNoContent,
		"[fd00::17]":                         http.StatusNoContent,
		"localhost:9090":                     http.StatusNoContent,
		"LOCALHOST":                          http.StatusNoContent,
		"byward-metrics.monitoring.svc:9090": http.StatusNoContent, // listed name, any port of up to 5 digits
		"127.1:9090":                         http.StatusNoContent, // an IP literal in any spelling
		"2130706433":                         http.StatusNoContent,
		"rebind.attacker.example:9090":       http.StatusMisdirectedRequest,
		"localhost.attacker.example":         http.StatusMisdirectedRequest,
		"127.0.0.1.nip.io:9090":              http.StatusMisdirectedRequest,
		"":                                   http.StatusMisdirectedRequest,
		// The internal listener's rule (ADR-0018 §2): any IP address in any spelling, localhost, and a
		// listed name in any case on any port of up to 5 digits (so :080 too); a full-width name, a trailing dot, a name
		// ending in a number and a non-ASCII name are refused.
		"BYWARD-METRICS.monitoring.svc":  http.StatusNoContent,
		"localhost:080":                  http.StatusNoContent,
		"ｌｏｃａｌｈｏｓｔ":                      http.StatusMisdirectedRequest,
		"byward-metrics.monitoring.svc.": http.StatusMisdirectedRequest,
		"mcp.10":                         http.StatusMisdirectedRequest,
		"bÿward-metrics.monitoring.svc":  http.StatusMisdirectedRequest,
		// The host is read from the Host header as a client writes it (#644): a port of up to 5 digits,
		// or none after the ":", passes; a bracketed name or IPv4 address, an unclosed or stray bracket,
		// or any other port names no host, and is refused, as is a shape CutHostname takes that names
		// no listed host or address (an empty host before a port, [not an address:]).
		"[::1]": http.StatusNoContent, "::1": http.StatusNoContent, "127.0.0.1:": http.StatusNoContent,
		// An IPv6 address with a zone, which a client strips before it sends Host (#652); without it, the address passes.
		"[fe80::1%eth0]:9090": http.StatusMisdirectedRequest, "[fe80::1%25eth0]:9090": http.StatusMisdirectedRequest, "[fe80::1]:9090": http.StatusNoContent,
		"127.0.0.1:65535": http.StatusNoContent, "byward-metrics.monitoring.svc:10250": http.StatusNoContent,
		"[byward-metrics.monitoring.svc]:9090": http.StatusMisdirectedRequest, "[mcp.example.com]:443": http.StatusMisdirectedRequest,
		"[127.0.0.1]:80": http.StatusMisdirectedRequest, "[0.0.0.0]": http.StatusMisdirectedRequest,
		":80": http.StatusMisdirectedRequest, "[not an address:]": http.StatusMisdirectedRequest,
		"[::1": http.StatusMisdirectedRequest, "::1]": http.StatusMisdirectedRequest, "127.1:443]": http.StatusMisdirectedRequest,
		"127.0.0.1:+80": http.StatusMisdirectedRequest, "127.0.0.1:-1": http.StatusMisdirectedRequest, "127.0.0.1:http": http.StatusMisdirectedRequest,
		"127.0.0.1:000080": http.StatusMisdirectedRequest, "127.0.0.1:99999999999999999999": http.StatusMisdirectedRequest,
		// A zoned address with a stray "]": main dropped the "]" and took the zoned address.
		"fe80::1%eth0]": http.StatusMisdirectedRequest, "FE80::1%25eth0]": http.StatusMisdirectedRequest,
	}
	for host, want := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withHost(host))
		if w.Code != want {
			t.Errorf("host %q: got %d want %d", host, w.Code, want)
		}
	}
	// A bracketed IPv6 address with junk after its port names no host, and is refused.
	for _, in := range []string{
		"[0:0::1]:443:",
		"[0:0::1]:443:8443",
		"[0:0::1]:443]",
		"[2001:DB8:0:0::1]:8443:",
		"[2001:DB8:0:0::1]:8443:8443",
		"[2001:DB8:0:0::1]:8443]",
		"[2001:db8:0:0:0:0:0:1]:80:",
		"[2001:db8:0:0:0:0:0:1]:80:8443",
		"[2001:db8:0:0:0:0:0:1]:80]",
		"[2001:db8::1]:4000:",
		"[2001:db8::1]:4000:8443",
		"[2001:db8::1]:4000]",
		"[2001:db8::1]:8443:",
		"[2001:db8::1]:8443:8443",
		"[2001:db8::1]:8443]",
		"[::1]:443:",
		"[::1]:443:8443",
		"[::1]:443]",
		"[::1]:65535:",
		"[::1]:65535:8443",
		"[::1]:65535]",
		"[::1]:8080:",
		"[::1]:8080:8443",
		"[::1]:8080]",
		"[::1]:80:",
		"[::1]:80:443",
		"[::1]:80:443:",
		"[::1]:80:443:8443",
		"[::1]:80:443]",
		"[::1]:80:8443",
		"[::1]:80]",
		"[::1]:8443:",
		"[::1]:8443:8443",
		"[::1]:8443]",
		"[::1]:9090:",
		"[::1]:9090:8443",
		"[::1]:9090]",
		"[::FFFF:1.2.3.4]:8080:",
		"[::FFFF:1.2.3.4]:8080:8443",
		"[::FFFF:1.2.3.4]:8080]",
		"[::FFFF:127.0.0.1]:8443:",
		"[::FFFF:127.0.0.1]:8443:8443",
		"[::FFFF:127.0.0.1]:8443]",
		"[::ffff:102:304]:8080:",
		"[::ffff:102:304]:8080:8443",
		"[::ffff:102:304]:8080]",
		"[::ffff:127.0.0.1]:80:",
		"[::ffff:127.0.0.1]:80:8443",
		"[::ffff:127.0.0.1]:80]",
		"[::ffff:127.0.0.1]:8443:",
		"[::ffff:127.0.0.1]:8443:8443",
		"[::ffff:127.0.0.1]:8443]",
		"[::ffff:7f00:1]:8443:",
		"[::ffff:7f00:1]:8443:8443",
		"[::ffff:7f00:1]:8443]",
		"[FE80::1]:8443:",
		"[FE80::1]:8443:8443",
		"[FE80::1]:8443]",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withHost(in))
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d, want 421", in, w.Code)
		}
	}
}

// An IPv6 address with a zone is refused whatever the allowed list holds: config refuses a zoned
// entry, and the internal listener does not rely on it (#652).
func TestTheInternalListenerRefusesAZoneEvenWhenTheListNamesIt(t *testing.T) {
	w := httptest.NewRecorder()
	InternalHosts(quiet(), []string{"[fe80::1%eth0]:9090"}, ok).ServeHTTP(w, withHost("[fe80::1%eth0]:9090"))
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a zoned Host the list names: %d, want 421", w.Code)
	}
}

func TestOriginOutsideAllowlistGets403(t *testing.T) {
	h := Origins(quiet(), []string{"https://app.example"}, ok)
	cases := []struct {
		name    string
		origins []string
		want    int
	}{
		{"missing passes", nil, http.StatusNoContent},
		{"allowed", []string{"https://app.example"}, http.StatusNoContent},
		{"case-insensitive", []string{"HTTPS://APP.EXAMPLE"}, http.StatusNoContent},
		{"other origin", []string{"https://evil.example"}, http.StatusForbidden},
		{"other port", []string{"https://app.example:8443"}, http.StatusForbidden},
		{"other scheme", []string{"http://app.example"}, http.StatusForbidden},
		{"null", []string{"null"}, http.StatusForbidden},
		{"multiple", []string{"https://app.example", "https://app.example"}, http.StatusForbidden},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/mcp", nil)
		for _, o := range c.origins {
			r.Header.Add("Origin", o)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, w.Code, c.want)
		}
	}
}

func TestEmptyOriginAllowlistRejectsBrowsers(t *testing.T) {
	h := Origins(quiet(), nil, ok)
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "http://localhost:6274")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d", w.Code)
	}
}

func TestListedOriginGetsCORSAndPreflight(t *testing.T) {
	reached := false
	h := Origins(quiet(), []string{"https://app.example"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	r := preflight("https://app.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || reached || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: code=%d reached=%v headers=%v", w.Code, reached, w.Header())
	}
	r = httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "https://app.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !reached || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate") || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("actual request: headers=%v", w.Header())
	}
	// Only a preflight is told the allowed headers, and only its answer varies with the requested ones.
	if w.Header().Get("Access-Control-Allow-Headers") != "" || !slices.Equal(w.Header().Values("Vary"), []string{"Origin"}) {
		t.Fatalf("actual request: Access-Control-Allow-Headers %q, Vary %q; want none and [Origin]", w.Header().Get("Access-Control-Allow-Headers"), w.Header().Values("Vary"))
	}
}

// A browser MCP client mirrors tool parameters into Mcp-Param-{name} headers (MCP 2026-07-28), a
// family no fixed Access-Control-Allow-Headers can name: the preflight allows the Mcp-Param-* names
// it requests that are valid header names within the caps (at most 32 distinct names of at most
// 128 bytes), beside the fixed list, and no other name it requests.
func TestAPreflightAllowsOnlyTheValidMcpParamHeadersItRequestsWithinTheCaps(t *testing.T) {
	// The fixed list a browser MCP client needs, written out: built from the code's list
	// (config.MCPRequestHeaders), a dropped name would pass unnoticed.
	const fixed = "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Mcp-Method, Mcp-Name, Last-Event-ID"
	atCap := "mcp-param-" + strings.Repeat("a", 128-len("mcp-param-")) // 128 bytes
	many := make([]string, 37)
	for i := range many {
		many[i] = fmt.Sprintf("mcp-param-p%03d", i)
	}
	for _, tc := range []struct {
		name      string
		requested []string // Access-Control-Request-Headers lines
		want      []string // the names allowed after the fixed list
	}{
		{"none requested", nil, nil},
		{"only fixed headers requested", []string{"authorization,content-type"}, nil},
		{"one, as a browser sends it", []string{"authorization,content-type,mcp-param-region"}, []string{"mcp-param-region"}},
		{"several, spaced and on two lines", []string{"Mcp-Param-Region, mcp-param-zone", "mcp-param-tenant"}, []string{"Mcp-Param-Region", "mcp-param-zone", "mcp-param-tenant"}},
		{"a repeat in another case is listed once, as first sent", []string{"MCP-PARAM-REGION,mcp-param-region"}, []string{"MCP-PARAM-REGION"}},
		{"another family is never echoed", []string{"x-api-key,cookie,mcp-paramregion,mcp-sessionid,x-mcp-param-region"}, nil},
		{"the bare prefix is not a parameter", []string{"mcp-param-"}, nil},
		{"a name that is not a header token", []string{"mcp-param-a b,mcp-param-a\"b,mcp-param-é"}, nil},
		{"a name at the length cap", []string{atCap}, []string{atCap}},
		{"a name one byte over the length cap", []string{atCap + "a,mcp-param-ok"}, []string{"mcp-param-ok"}},
		// Refused names ahead of the list: the cap counts the names allowed, not those requested.
		{"names past the count cap", []string{"authorization,mcp-param-a b,mcp-param-p000," + strings.Join(many, ",")}, many[:32]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			Origins(quiet(), []string{"https://app.example"}, ok).ServeHTTP(w, preflight("https://app.example", tc.requested...))
			want := fixed
			if len(tc.want) > 0 {
				want += ", " + strings.Join(tc.want, ", ")
			}
			if got := w.Header().Values("Access-Control-Allow-Headers"); w.Code != http.StatusNoContent || len(got) != 1 || got[0] != want {
				t.Fatalf("status %d, Access-Control-Allow-Headers %q, want 204 and %q", w.Code, got, want)
			}
			if got := w.Header().Values("Vary"); !slices.Equal(got, []string{"Origin", "Access-Control-Request-Headers"}) {
				t.Fatalf("Vary %q, want [Origin Access-Control-Request-Headers]: the answer depends on both", got)
			}
		})
	}
}

// An origin that is not listed is refused with no CORS answer, whatever Mcp-Param-* names its
// preflight requests.
func TestAnUnlistedOriginsPreflightIsRefusedWhateverMcpParamHeadersItRequests(t *testing.T) {
	w := httptest.NewRecorder()
	Origins(quiet(), []string{"https://app.example"}, ok).ServeHTTP(w, preflight("https://evil.example", "mcp-param-region"))
	if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Headers") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("status %d, headers %v; want 403 and no CORS", w.Code, w.Header())
	}
}

func TestNoCORSWithoutOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	Origins(quiet(), []string{"https://app.example"}, ok).ServeHTTP(w, httptest.NewRequest("OPTIONS", "/mcp", nil))
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS headers without an Origin")
	}
}

func TestOriginRejectionNamesTheFix(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	Origins(quiet(), nil, ok).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "BYWARD_ALLOWED_ORIGINS") {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
}

func recording() (*audit.Log, *strings.Builder) {
	var b strings.Builder
	return audit.New(slog.New(slog.NewJSONHandler(&b, nil)), nil, time.Now), &b
}

func TestRejectionsAreAudited(t *testing.T) {
	rec, out := recording()
	hosts := Hosts(rec, []string{"mcp.example.com"}, ok)
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Host = "evil.example"
	hosts.ServeHTTP(httptest.NewRecorder(), r)
	origins := Origins(rec, []string{"https://app.example"}, ok)
	r = httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "https://evil.example")
	origins.ServeHTTP(httptest.NewRecorder(), r)
	for _, want := range []string{`"event":"host_rejected","outcome":"failure","host":"evil.example"`,
		`"event":"origin_rejected","outcome":"failure","origin":"https://evil.example"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("audit stream lacks %s:\n%s", want, out.String())
		}
	}
}

func TestAllowedRequestsAreNotAudited(t *testing.T) {
	rec, out := recording()
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Host = "mcp.example.com"
	r.Header.Set("Origin", "https://app.example")
	Hosts(rec, []string{"mcp.example.com"}, Origins(rec, []string{"https://app.example"}, ok)).ServeHTTP(httptest.NewRecorder(), r)
	if out.Len() != 0 {
		t.Fatalf("an allowed request produced audit records: %s", out.String())
	}
}

// The Host check folds case, an IP address's spelling and one default port, and nothing more: a
// default port with leading zeros, an empty port, a sign or an out-of-range port, a full-width or
// Unicode name and a trailing dot match nothing (#523), so a switch to a wider fold shows here.
func TestTheHostCheckFoldsCaseAddressSpellingAndOneDefaultPortAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		listed string
		refuse []string
	}{
		{"mcp.example.com", []string{"mcp.example.com:080", "mcp.example.com:0443", "mcp.example.com:00080", "mcp.example.com:", "ｍｃｐ.example.com",
			"mcp.example.com:+443", "mcp.example.com:99999", "mcp.example.com."}},
		{"xn--bcher-kva.example", []string{"bücher.example"}},
		{"[::1]", []string{"[::1]:"}},
	} {
		t.Run(tc.listed, func(t *testing.T) { matchesOnly(t, tc.listed, nil, tc.refuse) })
	}
}

// originCode is Origins' answer to one Origin header against listed.
func originCode(listed []string, o string) (int, http.Header) {
	w := httptest.NewRecorder()
	Origins(quiet(), listed, ok).ServeHTTP(w, withOrigin(o))
	return w.Code, w.Header()
}

// An Origin matches its listed entry once folded (ADR-0032 A3): in any case, with an IPv4 or IPv6
// address in any spelling, and with the scheme's own default port. Anything that is no bare origin, a
// spelling the fold leaves apart, another scheme's default port or another origin matches nothing.
func TestAnOriginMatchesItsEntryOnceFoldedAndNothingElse(t *testing.T) {
	shared := []string{"https://127.0.0.1", "https://[::1]", "https://app.example", "http://plain.example", "https://xn--bcher-kva.example"}
	for _, tc := range []struct {
		origin string
		want   int
		listed []string // shared when nil
	}{
		{"https://127.1", http.StatusNoContent, nil},
		{"https://0x7f.0.0.1", http.StatusNoContent, nil},
		{"https://[0:0::1]", http.StatusNoContent, nil},
		{"https://APP.Example", http.StatusNoContent, nil},
		{"https://app.example:443", http.StatusNoContent, nil},
		{"http://plain.example:80", http.StatusNoContent, nil},
		// No bare origin.
		{"https://app.example/", http.StatusForbidden, nil},
		{"https://app.example/mcp", http.StatusForbidden, nil},
		{"https://u@app.example", http.StatusForbidden, nil},
		{"https://app.example?x=1", http.StatusForbidden, nil},
		{"https://app.example?", http.StatusForbidden, nil},
		{"https://app.example#f", http.StatusForbidden, nil},
		{"app.example", http.StatusForbidden, nil},
		// Spellings no browser sends, as the Host check does not fold them either.
		{"https://app.example:0443", http.StatusForbidden, nil},
		{"https://app.example:", http.StatusForbidden, nil},
		{"https://[::1]:", http.StatusForbidden, nil},
		{"https://ａｐｐ.example", http.StatusForbidden, nil},
		{"https://bücher.example", http.StatusForbidden, nil},
		// Only the scheme's own default port.
		{"https://app.example:80", http.StatusForbidden, nil},
		{"http://plain.example:443", http.StatusForbidden, nil},
		// A spelling of an origin that is not listed.
		{"https://127.1", http.StatusForbidden, []string{"https://127.0.0.2"}},
	} {
		listed := tc.listed
		if listed == nil {
			listed = shared
		}
		if code, _ := originCode(listed, tc.origin); code != tc.want {
			t.Errorf("Origin %q against %q: got %d, want %d", tc.origin, listed, code, tc.want)
		}
	}
}

// An allowed entry that is no bare origin matches nothing: not the bare origin it would be without its
// trailing slash, and never a header that is no origin either (null, a path, another scheme) by sharing
// its empty key.
func TestAMalformedAllowedOriginMatchesNoHeader(t *testing.T) {
	for _, o := range []string{"https://app.example", "null", "https://evil.example/x", "ftp://app.example", "https://"} {
		if code, _ := originCode([]string{"https://app.example/", "https://", "ftp://app.example"}, o); code != http.StatusForbidden {
			t.Errorf("Origin %q against malformed entries: got %d, want 403", o, code)
		}
	}
}

// The CORS answer echoes the Origin exactly as the client sent it, never its folded form: a browser
// compares Access-Control-Allow-Origin with the Origin it sent, byte for byte.
func TestCORSEchoesTheOriginAsSent(t *testing.T) {
	for _, o := range []string{"https://127.1", "https://APP.example", "https://app.example:443"} {
		code, h := originCode([]string{"https://127.0.0.1", "https://app.example"}, o)
		if code != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != o {
			t.Errorf("Origin %q: got %d, Access-Control-Allow-Origin %q; want it echoed as sent", o, code, h.Get("Access-Control-Allow-Origin"))
		}
	}
}

// A Host or Origin with a stray bracket, one no browser sends, is refused by every check, as on main
// before #644 made host.Split the one bracket rule: the same inputs host's strayBracketHosts pins.
func TestAHostOrOriginWithAStrayBracketIsRefusedByEveryCheck(t *testing.T) {
	hosts := []string{"127.0.0.1:443", "127.0.0.1:8080", "127.0.0.1", "mcp.example.com", "app.example", "localhost:8080", "[::1]:8080"}
	origins := []string{"https://app.example", "https://mcp.example.com", "http://127.0.0.1:8080"}
	pub, internal, cors := Hosts(quiet(), hosts, ok), InternalHosts(quiet(), hosts, ok), Origins(quiet(), origins, ok)
	// Controls: a spelling each check folds passes without a stray bracket, so the refusals below are
	// the bracket's, not the spelling's.
	for _, tc := range []struct {
		check string
		h     http.Handler
		r     *http.Request
	}{
		{"public", pub, withHost("127.1:443")}, {"internal", internal, withHost("127.1:8080")},
		{"origin", cors, withOrigin("HTTPS://APP.EXAMPLE")},
	} {
		w := httptest.NewRecorder()
		tc.h.ServeHTTP(w, tc.r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s without the stray bracket: %d, want 204", tc.check, w.Code)
		}
	}
	for _, in := range []string{
		"127.1:443]",
		"127.1:8080]",
		"2130706433:8080]",
		"0x7f.0.0.1:8080]",
		"0177.0.0.1:8080]",
		"127.1:9090]",
		"HTTPS://APP.EXAMPLE]",
		"https://APP.Example]",
		"https://APP.example]",
		"Origin %q: got %d, Access-Control-Allow-Origin %q; want it echoed as sent]",
		"BYWARD_PUBLIC_URL=https://MCP.Example.com/mcp]",
		"BYWARD_PUBLIC_URL=https://b%C3%BCcher.example/mcp]",
		"BYWARD_ALLOWED_ORIGINS=https://192.168.0.0xFF]",
		"(12 CHARACTERS, NOT SHOWN): IT HAS A \"[\" IN ITS HOST WITHOUT ITS \"]\"",
		"(18 characters, not shown): it has a control character, which a URL cannot hold]",
		"(10 characters, not shown): it is not an IPv6 address without a zone; ]",
		"(19 characters, not shown): it is not an IPv6 address without a zone; ]",
		"(12 characters, not shown): it is not an IPv6 address without a zone; ]",
		"(5 characters, not shown): it is not an IPv6 address without a zone; ]",
		"HTTPS://XN--BCHER-KVA.example]",
		"without dev: want error pointing at the _FILE variable, got %v]",
		" (14 characters, not shown): it is neither a CIDR nor an IP address]",
		" (8 characters, not shown): its address, before the \"/\", is not an IP address]",
		"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read]",
	} {
		for _, tc := range []struct {
			check string
			h     http.Handler
			r     *http.Request
			want  int
		}{
			{"public", pub, withHost(in), http.StatusMisdirectedRequest},
			{"internal", internal, withHost(in), http.StatusMisdirectedRequest},
			{"origin", cors, withOrigin(in), http.StatusForbidden},
		} {
			w := httptest.NewRecorder()
			tc.h.ServeHTTP(w, tc.r)
			if w.Code != tc.want {
				t.Errorf("%s %q: %d, want %d", tc.check, in, w.Code, tc.want)
			}
		}
	}
}

func withHost(h string) *http.Request {
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Host = h
	return r
}

func withOrigin(o string) *http.Request {
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", o)
	return r
}
