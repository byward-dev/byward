package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/token"
)

func TestPercentEncodingLeavesOnlyUnreservedCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"byward.user":          "byward.user",
		"A-Z_a~z.0-9":          "A-Z_a~z.0-9",
		"tid:oid":              "tid%3Aoid",
		"Data,Read":            "Data%2CRead",
		"Renée M":              "Ren%C3%A9e%20M",
		"x\r\nX-Evil: 1":       "x%0D%0AX-Evil%3A%201",
		"a%2C":                 "a%252C",
		"alex@contoso.example": "alex%40contoso.example",
	} {
		if got := percentEncode(in); got != want {
			t.Errorf("percentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

// decoded reads a plain identity header as an upstream would: split on commas, then URL-decode.
func decoded(t *testing.T, h http.Header, name string) []string {
	t.Helper()
	raw := h.Values(name)
	if len(raw) == 0 {
		return nil
	}
	if len(raw) != 1 {
		t.Fatalf("%s sent %d times", name, len(raw))
	}
	var out []string
	for _, item := range strings.Split(raw[0], ",") {
		v, err := url.PathUnescape(item)
		if err != nil {
			t.Fatalf("%s: %q does not decode: %v", name, item, err)
		}
		out = append(out, v)
	}
	return out
}

func asStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, len(v))
		for i, s := range v {
			out[i], _ = s.(string)
		}
		return out
	}
	return nil
}

// With BYWARD_IDENTITY_HEADERS the upstream reads the same user from plain headers as from the
// assertion, even values with commas, line breaks or non-ASCII; and a client's copies, in any
// spelling, never get through (ADR-0016 §5).
func TestPlainIdentityHeadersCarryTheAssertionsClaimsAndNeverTheClients(t *testing.T) {
	a := newAsserting(t, "BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_CLAIMS=roles,groups,email,name")
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "https://claude.ai/oauth/client", Roles: []string{"byward.user", "Data,Read"},
		Groups: []string{"g-1", "g-2"}, Email: "alex@contoso.example", Name: "Renée\r\nX-Evil: 1"},
		http.Header{"X-Byward-Subject": {"tid:someone-else"}, "X_byward_roles": {"admin"}, "X-Evil": {"forged"}})
	if _, ok := got.Header["X_byward_roles"]; ok {
		t.Fatal("the client's X_byward_roles reached the upstream")
	}
	raw, _ := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
	c := verified(t, jwks(t, a.public, "mcp.example.com"), raw, a.cfg.UpstreamURL.String())
	for header, claim := range map[string]string{config.HeaderSubject: "sub", config.HeaderClientID: "client_id", config.HeaderRoles: "roles",
		config.HeaderGroups: "groups", config.HeaderEmail: "email", config.HeaderName: "name"} {
		if d, want := decoded(t, got.Header, header), asStrings(c[claim]); !reflect.DeepEqual(d, want) || len(want) == 0 {
			t.Errorf("%s = %q, the assertion's %s = %q", header, d, claim, want)
		}
	}
	if !strings.Contains(a.logs.String(), "plain identity headers are on") {
		t.Fatalf("no startup warning in:\n%s", a.logs)
	}
}

// A claim the user's token does not carry gets no header, never an empty one.
func TestAnAbsentClaimSendsNoPlainHeader(t *testing.T) {
	a := newAsserting(t, "BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_CLAIMS=roles,groups,email,name")
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "c"}, nil)
	for _, h := range []string{config.HeaderRoles, config.HeaderGroups, config.HeaderEmail, config.HeaderName} {
		if v, ok := got.Header[h]; ok {
			t.Errorf("%s = %q, want no header", h, v)
		}
	}
	if got.Header.Get(config.HeaderSubject) != "tid%3Aoid" || got.Header.Get(config.HeaderClientID) != "c" {
		t.Fatalf("subject %q client %q", got.Header.Get(config.HeaderSubject), got.Header.Get(config.HeaderClientID))
	}
}

// Off (the default), the proxy sends none, and still removes every copy a client sends, so turning
// them on or off never lets a forged one through.
func TestWithPlainIdentityHeadersOffAClientsCopiesAreStillRemoved(t *testing.T) {
	forged := http.Header{"X-Byward-Subject": {"tid:someone-else"}, "X_byward_roles": {"admin"}}
	a := newAsserting(t)
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "c", Roles: []string{"byward.user"}}, forged)
	for k := range got.Header {
		if strings.HasPrefix(strings.ReplaceAll(strings.ToLower(k), "_", "-"), "x-byward-") {
			t.Errorf("%s reached the upstream", k)
		}
	}
	if strings.Contains(a.logs.String(), "plain identity headers are on") {
		t.Fatal("the startup warning with the headers off")
	}

	// Without authentication too.
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + up.URL + "/mcp", "BYWARD_INSECURE_NO_AUTH=true"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range forged {
		r.Header[k] = v
	}
	s, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	s.Public.Handler.ServeHTTP(httptest.NewRecorder(), r)
	got, ok := up.Last()
	if !ok {
		t.Fatal("the upstream got no request")
	}
	for k := range got.Header {
		if strings.HasPrefix(strings.ReplaceAll(strings.ToLower(k), "_", "-"), "x-byward-") {
			t.Errorf("without authentication, %s reached the upstream", k)
		}
	}
}

// doctor's hint: an upstream host with only non-public addresses passes; a public one, or one that
// does not resolve, warns; every message says it is a hint.
func TestDoctorWarnsWhenPlainIdentityHeadersGoToAPublicHost(t *testing.T) {
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "mcp.internal":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("fd00::5")}, nil
		case "mixed.example":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8")}, nil
		}
		return nil, errors.New("no such host")
	}
	for _, tc := range []struct {
		upstream string
		want     doctor.Status
		inMsg    string
	}{
		{"http://127.0.0.1:9000/mcp", doctor.Pass, "only loopback, private, link-local or shared addresses"},
		{"http://[::1]:9000/mcp", doctor.Pass, "only loopback"},
		{"http://10.1.2.3/mcp", doctor.Pass, "only loopback"},
		{"http://100.64.1.1/mcp", doctor.Pass, "only loopback"},
		{"http://169.254.1.1/mcp", doctor.Pass, "only loopback"},
		{"http://[fe80::1]/mcp", doctor.Pass, "only loopback"},
		{"http://mcp.internal/mcp", doctor.Pass, "only loopback"},
		{"http://8.8.8.8/mcp", doctor.Warn, "has the public address 8.8.8.8"},
		{"http://[::ffff:8.8.8.8]/mcp", doctor.Warn, "has the public address 8.8.8.8"},
		{"https://mixed.example/mcp", doctor.Warn, "has the public address 8.8.8.8"},
		{"https://gone.example/mcp", doctor.Warn, "does not resolve here"},
	} {
		t.Run(tc.upstream, func(t *testing.T) {
			u, _ := url.Parse(tc.upstream)
			r := identityHeadersResult(context.Background(), &config.Config{UpstreamURL: u, IdentityHeaders: true}, resolve)
			if r.Status != tc.want || !strings.Contains(r.Message, tc.inMsg) || !strings.Contains(r.Message, "a hint, not a guarantee") {
				t.Fatalf("%s: %s", r.Status, r.Message)
			}
			if (r.Status == doctor.Warn) != (r.Fix != "") {
				t.Fatalf("fix %q for status %s", r.Fix, r.Status)
			}
		})
	}
}

// doctor runs the hint only while the plain identity headers are on.
func TestDoctorChecksTheUpstreamHostOnlyWithPlainIdentityHeadersOn(t *testing.T) {
	private := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	for _, on := range []bool{false, true} {
		var extra []string
		if on {
			extra = append(extra, "BYWARD_IDENTITY_HEADERS=true")
		}
		r := runProxy(t, extra...)
		rep, err := Doctor(context.Background(), r.cfg, DoctorOptions{IdP: r.fake.HTTPClient(), Resolve: private})
		if err != nil {
			t.Fatal(err)
		}
		var found *doctor.Result
		for _, c := range rep.Checks {
			if c.Name == "identity headers" {
				found = &c
			}
		}
		if (found != nil) != on || (on && found.Status != doctor.Pass) {
			t.Fatalf("headers on %v: identity headers check %+v", on, found)
		}
	}
}
