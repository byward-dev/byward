package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/token"
)

// An MCP client cannot reach the upstream with a request trailer named like a header the proxy sets
// (the identity assertion, the upstream credential, every plain identity header) or like any other
// name: the upstream gets no trailers at all, and each of those headers only as the proxy set it.
func TestATrailerNamedLikeAProxySetHeaderNeverReachesTheUpstream(t *testing.T) {
	a := newAsserting(t, "BYWARD_IDENTITY_HEADERS=true", "BYWARD_ASSERTION_CLAIMS="+strings.Join(config.AssertionClaimNames, ","),
		"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key", "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credentialFile(t, 0o600))
	srv := httptest.NewServer(a.public)
	t.Cleanup(srv.Close)
	now := time.Now()
	tok, err := a.sealer.Seal(token.Access, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "claude-code", Roles: []string{"byward.user"},
		Email: "alex@contoso.example", Name: "Alex", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// X-Not-Ours: the drop covers every name, not only the ones the proxy strips.
	names := append([]string{a.cfg.AssertionHeader, "X-Api-Key", "X-Not-Ours"}, config.IdentityHeaderNames...)

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", io.NopCloser(strings.NewReader(body))) // no length: chunked, with trailers
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "mcp.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Trailer = http.Header{}
	for _, n := range names {
		req.Trailer.Set(n, "forged")
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got, ok := a.up.Last()
	if res.StatusCode != http.StatusOK || !ok {
		t.Fatalf("status %d, upstream reached %v", res.StatusCode, ok)
	}
	if len(got.Trailer) != 0 || string(got.Body) != body {
		t.Fatalf("trailers %v, body %q reached the upstream", got.Trailer, got.Body)
	}
	for _, n := range names { // a regression guard: the proxy never copies a trailer into the headers
		if v := got.Header.Values(n); slices.Contains(v, "forged") || len(v) > 1 {
			t.Errorf("%s at the upstream: %q, want at most the proxy's own value", n, v)
		}
	}
	if got.Header.Get("X-Api-Key") != upstreamCredential || !strings.HasPrefix(got.Header.Get(a.cfg.AssertionHeader), "Bearer ") {
		t.Fatalf("credential %q, assertion %q: the proxy's own headers are missing", got.Header.Get("X-Api-Key"), got.Header.Get(a.cfg.AssertionHeader))
	}
}
