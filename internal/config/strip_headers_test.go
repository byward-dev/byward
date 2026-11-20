package config

import (
	"slices"
	"testing"
)

// The operator's strip list is read in any case and `_` spelling, into the names the relay
// compares; nothing is stripped by default.
func TestTheUpstreamStripListIsReadAsCanonicalHeaderNames(t *testing.T) {
	c, err := load(t, nil)
	if err != nil || len(c.UpstreamStripHeaders) != 0 {
		t.Fatalf("default %q (%v), want none", c.UpstreamStripHeaders, err)
	}
	c, err = load(t, nil, "BYWARD_UPSTREAM_STRIP_HEADERS= x-argocd-base-url, TFE_TOKEN ,,opensearch-url,mcp-params,x-tenant-param-id")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"X-Argocd-Base-Url", "Tfe-Token", "Opensearch-Url", "Mcp-Params", "X-Tenant-Param-Id"}; !slices.Equal(c.UpstreamStripHeaders, want) {
		t.Fatalf("got %q, want %q", c.UpstreamStripHeaders, want)
	}
}

// A header MCP needs at the upstream, a header tracing sets, a pattern and a name that is no
// header are refused, each named. With a stdio upstream the list is refused as an off-mode setting
// (offmode_test.go).
func TestTheUpstreamStripListRefusesWhatCannotBeStripped(t *testing.T) {
	const want = "BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got "
	const needed, traced = ": MCP needs it at the upstream; remove it from the list", ": with tracing on, the proxy sets it from the inbound trace context; remove it from the list"
	// A header MCP or tracing relies on is shown as the upstream reads it; a refused name is never shown.
	for _, tc := range []struct{ name, list, want string }{
		{"Accept", "accept", "entry 1 of 1, Accept" + needed},
		{"Content-Type", "Content-Type", "entry 1 of 1, Content-Type" + needed},
		{"Content-Length", "content-length", "entry 1 of 1, Content-Length" + needed},
		{"Transfer-Encoding", "transfer-encoding", "entry 1 of 1, Transfer-Encoding" + needed},
		{"Host", "host", "entry 1 of 1, Host" + needed},
		{"Last-Event-ID", "Last-Event-ID", "entry 1 of 1, Last-Event-Id" + needed},
		{"the session", "mcp_session_id", "entry 1 of 1, Mcp-Session-Id" + needed},
		{"the protocol version", "MCP-Protocol-Version", "entry 1 of 1, Mcp-Protocol-Version" + needed},
		{"the method", "mcp-method", "entry 1 of 1, Mcp-Method" + needed},
		{"the name", "Mcp-Name", "entry 1 of 1, Mcp-Name" + needed},
		{"a tool parameter, by its family", "X-Ok, mcp-param-region", "entry 2 of 2, a header starting Mcp-Param-" + needed},
		{"a pattern", "X-Atlassian-*", "entry 1 of 1 (13 characters, not shown): it has a *: list each header of a family by name"},
		{"a pattern inside a name", "X-Atlassian-*-Url", "entry 1 of 1 (17 characters, not shown): it has a *: list each header of a family by name"},
		{"a name with a colon", "X-Api-Key:", "entry 1 of 1 (10 characters, not shown): it is not a header name"},
		{"a name with another separator", "X(Url)", "entry 1 of 1 (6 characters, not shown): it is not a header name"},
		{"a name that is not ASCII", "X-Idé", "entry 1 of 1 (5 characters, not shown): it is not a header name"},
		{"the trace context", "traceparent", "entry 1 of 1, Traceparent" + traced},
		{"the trace state", "TRACESTATE", "entry 1 of 1, Tracestate" + traced},
		{"not a header", "X Api Key", "entry 1 of 1 (9 characters, not shown): it is not a header name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, nil, "BYWARD_UPSTREAM_STRIP_HEADERS="+tc.list)
			if err == nil || err.Error() != want+tc.want {
				t.Fatalf("error %v, want %q", err, want+tc.want)
			}
		})
	}
}
