package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/token"
)

// A client cannot reach the upstream with a request trailer named like any header the proxy sets
// for it, the assertion, the operator's credential and every plain identity header: the upstream
// gets no trailers at all, and each of those headers only as the proxy set it.
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
	names := append([]string{a.cfg.AssertionHeader, "X-Api-Key"}, config.IdentityHeaderNames...)

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	var trailers strings.Builder
	for _, n := range names {
		trailers.WriteString(n + ": forged\r\n")
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req := "POST /mcp HTTP/1.1\r\nHost: mcp.example.com\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n" +
		"Authorization: Bearer " + tok + "\r\nTransfer-Encoding: chunked\r\nTrailer: " + strings.Join(names, ", ") + "\r\nConnection: close\r\n\r\n" +
		strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n" + trailers.String() + "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got, ok := a.up.Last()
	if res.StatusCode != http.StatusOK || !ok {
		t.Fatalf("status %d, upstream reached %v", res.StatusCode, ok)
	}
	if len(got.Trailer) != 0 || got.Header.Get("Trailer") != "" || string(got.Body) != body {
		t.Fatalf("trailers %v, Trailer header %q, body %q reached the upstream", got.Trailer, got.Header.Get("Trailer"), got.Body)
	}
	for _, n := range names {
		if v := got.Header.Values(n); slices.Contains(v, "forged") || len(v) > 1 {
			t.Errorf("%s at the upstream: %q, want at most the proxy's own value", n, v)
		}
	}
	if got.Header.Get("X-Api-Key") != upstreamCredential || !strings.HasPrefix(got.Header.Get(a.cfg.AssertionHeader), "Bearer ") {
		t.Fatalf("credential %q, assertion %q: the proxy's own headers are missing", got.Header.Get("X-Api-Key"), got.Header.Get(a.cfg.AssertionHeader))
	}
}
