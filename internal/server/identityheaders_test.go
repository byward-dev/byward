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
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/token"
)

// headerOfClaim is which plain identity header carries which assertion claim: the names as
// documented (docs/how-to/plain-identity-headers.md), which upstreams read.
var headerOfClaim = map[string]string{"sub": "X-Byward-Subject", "client_id": "X-Byward-Client-Id", "roles": "X-Byward-Roles",
	"groups": "X-Byward-Groups", "email": "X-Byward-Email", "name": "X-Byward-Name"}

// forgedIdentityHeaders is a client's copy of every plain identity header, and one in `_` spelling.
func forgedIdentityHeaders() http.Header {
	h := http.Header{"X_byward_roles": {"admin"}}
	for _, name := range config.IdentityHeaderNames {
		h[name] = []string{"forged"}
	}
	return h
}

// byward reports whether an upstream header is in the proxy's X-Byward-* family.
func byward(name string) bool {
	return strings.HasPrefix(strings.ReplaceAll(strings.ToLower(name), "_", "-"), "x-byward-")
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
// assertion, every claim of it, even values with commas, line breaks, non-ASCII or an empty list
// item; and no client's copy, in any spelling, gets through (ADR-0016 §5).
func TestPlainIdentityHeadersCarryTheAssertionsClaimsAndNeverAClientsCopies(t *testing.T) {
	for _, claim := range config.AssertionClaimNames {
		if headerOfClaim[claim] == "" {
			t.Fatalf("the assertion claim %q has no plain identity header", claim)
		}
	}
	a := newAsserting(t, "BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_CLAIMS="+strings.Join(config.AssertionClaimNames, ","))
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "https://claude.ai/oauth/client", Roles: []string{"byward.user", "Data,Read", ""},
		Groups: []string{"g-1", "g-2"}, Email: "alex@contoso.example", Name: "Renée\r\nX-Evil: 1"}, forgedIdentityHeaders())
	for k := range got.Header {
		if byward(k) && !slices.Contains(config.IdentityHeaderNames, k) {
			t.Errorf("%s reached the upstream", k)
		}
	}
	raw, _ := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
	c := verified(t, jwks(t, a.public, "mcp.example.com"), raw, a.cfg.UpstreamURL.String())
	for claim, header := range headerOfClaim {
		if d, want := decoded(t, got.Header, header), asStrings(c[claim]); !reflect.DeepEqual(d, want) || len(want) == 0 {
			t.Errorf("%s = %q, the assertion's %s = %q", header, d, claim, want)
		}
	}
}

// Every byte outside A-Z a-z 0-9 - . _ ~ reaches the upstream as %XX, so no value can end the
// header, add an item or add a header.
func TestPlainIdentityHeaderValuesArePercentEncoded(t *testing.T) {
	a := newAsserting(t, "BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_CLAIMS=name")
	for in, want := range map[string]string{
		"A-Z_a~z.0-9":          "A-Z_a~z.0-9",
		"Data,Read":            "Data%2CRead",
		"Renée M":              "Ren%C3%A9e%20M",
		"x\r\nX-Evil: 1":       "x%0D%0AX-Evil%3A%201",
		"a%2C":                 "a%252C",
		"alex@contoso.example": "alex%40contoso.example",
	} {
		got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "c", Name: in}, nil)
		if v := got.Header.Get(config.HeaderName); v != want {
			t.Errorf("name %q reached the upstream as %q, want %q", in, v, want)
		}
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

// A list of one empty item is still the claim: the header is sent, with an empty value.
func TestAListOfOneEmptyItemSendsAnEmptyHeader(t *testing.T) {
	a := newAsserting(t, "BYWARD_IDENTITY_HEADERS=true")
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "c", Roles: []string{""}}, nil)
	if v, ok := got.Header[config.HeaderRoles]; !ok || len(v) != 1 || v[0] != "" {
		t.Fatalf("%s = %q, %v; want one empty value", config.HeaderRoles, v, ok)
	}
}

// Off (the default), and without authentication, the proxy sends none and still removes every copy
// a client sends, so turning them on or off never lets a forged one through.
func TestWithPlainIdentityHeadersOffAClientsCopiesAreStillRemoved(t *testing.T) {
	for name, upstreamGot := range map[string]func(t *testing.T) http.Header{
		"authenticated, off": func(t *testing.T) http.Header {
			a := newAsserting(t)
			return a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "c", Roles: []string{"byward.user"}}, forgedIdentityHeaders()).Header
		},
		"without authentication": func(t *testing.T) http.Header {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			cfg, _, err := config.Load(nil, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + up.URL + "/mcp", "BYWARD_INSECURE_NO_AUTH=true"}, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			s, err := New(cfg, discard)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range forgedIdentityHeaders() {
				r.Header[k] = v
			}
			s.Public.Handler.ServeHTTP(httptest.NewRecorder(), r)
			got, ok := up.Last()
			if !ok {
				t.Fatal("the upstream got no request")
			}
			return got.Header
		},
	} {
		t.Run(name, func(t *testing.T) {
			for k := range upstreamGot(t) {
				if byward(k) {
					t.Errorf("%s reached the upstream", k)
				}
			}
		})
	}
}

// The operator sees the trade-off in the log whenever the headers are on, and only then.
func TestTurningOnPlainIdentityHeadersLogsAWarning(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want bool
	}{{"off", nil, false}, {"on", []string{"BYWARD_IDENTITY_HEADERS=true"}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAsserting(t, tc.env...)
			if got := strings.Contains(a.logs.String(), `level=WARN msg="plain identity headers are on"`); got != tc.want {
				t.Errorf("warning logged %v", got)
			}
		})
	}
}

// doctor's hint: an upstream host with only non-public addresses passes; a public one, or one that
// does not resolve, warns and names the setting; every message says it is a hint.
func TestDoctorPassesOnlyAnUpstreamHostWithNoPublicAddress(t *testing.T) {
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "mcp.internal":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("fd00::5")}, nil
		case "mixed.example":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8")}, nil
		case "empty.example":
			return nil, nil
		}
		return nil, errors.New("no such host")
	}
	for _, tc := range []struct {
		host  string
		want  doctor.Status
		inMsg string
	}{
		{"127.0.0.1", doctor.Pass, "only loopback, private, link-local or shared addresses"},
		{"::1", doctor.Pass, "only loopback"},
		{"10.1.2.3", doctor.Pass, "only loopback"},
		{"100.64.1.1", doctor.Pass, "only loopback"},
		{"169.254.1.1", doctor.Pass, "only loopback"},
		{"fe80::1", doctor.Pass, "only loopback"},
		{"mcp.internal", doctor.Pass, "only loopback"},
		{"8.8.8.8", doctor.Warn, "has the public address 8.8.8.8"},
		{"::ffff:8.8.8.8", doctor.Warn, "has the public address 8.8.8.8"},
		{"2001:4860:4860::8888", doctor.Warn, "has the public address 2001:4860:4860::8888"},
		{"mixed.example", doctor.Warn, "has the public address 8.8.8.8"},
		{"gone.example", doctor.Warn, "does not resolve here"},
		{"empty.example", doctor.Warn, "does not resolve here"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			r := identityHeadersResult(context.Background(), tc.host, resolve)
			if r.Status != tc.want || !strings.Contains(r.Message, tc.inMsg) || !strings.Contains(r.Message, "a hint, not a guarantee") {
				t.Fatalf("%s: %s", r.Status, r.Message)
			}
			if wantFix := r.Status == doctor.Warn; wantFix != strings.Contains(r.Fix, "BYWARD_IDENTITY_HEADERS") {
				t.Fatalf("fix %q for status %s", r.Fix, r.Status)
			}
		})
	}
}

// doctor runs the hint only while the plain identity headers are on.
func TestDoctorChecksTheUpstreamHostOnlyWithPlainIdentityHeadersOn(t *testing.T) {
	fake := fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}}))
	// Only the bare host name resolves: a host with its port would not, and warn.
	private := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "mcp.internal" {
			return nil, errors.New("no such host " + host)
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	for _, tc := range []struct {
		name      string
		env       []string
		wantCheck bool
	}{
		{"off", nil, false},
		{"on", []string{"BYWARD_IDENTITY_HEADERS=true", "BYWARD_UPSTREAM_URL=http://mcp.internal:8080/mcp"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadConfig(t, "https://mcp.example.com/mcp", tc.env...)
			rep, err := Doctor(context.Background(), cfg, DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}}, Resolve: private})
			if err != nil {
				t.Fatal(err)
			}
			var found *doctor.Result
			for _, c := range rep.Checks {
				if c.Name == "identity headers" {
					found = &c
				}
			}
			if (found != nil) != tc.wantCheck || (found != nil && found.Status != doctor.Pass) {
				t.Fatalf("identity headers check %+v", found)
			}
		})
	}
}
