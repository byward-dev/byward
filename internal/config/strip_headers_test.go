package config

import (
	"slices"
	"strings"
	"testing"
)

// The operator's strip list is read in any case and `_` spelling, into the names the relay
// compares; nothing is stripped by default.
func TestTheUpstreamStripListIsReadAsCanonicalHeaderNames(t *testing.T) {
	c, err := load(t, nil)
	if err != nil || len(c.UpstreamStripHeaders) != 0 {
		t.Fatalf("default %q (%v), want none", c.UpstreamStripHeaders, err)
	}
	c, err = load(t, nil, "BYWARD_UPSTREAM_STRIP_HEADERS= x-argocd-base-url, TFE_TOKEN ,,opensearch-url")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"X-Argocd-Base-Url", "Tfe-Token", "Opensearch-Url"}; !slices.Equal(c.UpstreamStripHeaders, want) {
		t.Fatalf("got %q, want %q", c.UpstreamStripHeaders, want)
	}
}

// A header MCP needs at the upstream, a pattern and a name that is no header are refused, each
// named; so is the list with a stdio upstream, which gets no request headers.
func TestTheUpstreamStripListRefusesWhatCannotBeStripped(t *testing.T) {
	for _, tc := range []struct{ name, list, want string }{
		{"Accept", "accept", "Accept is a header MCP needs"},
		{"Content-Type", "Content-Type", "Content-Type is a header MCP needs"},
		{"Content-Length", "content-length", "Content-Length is a header MCP needs"},
		{"Transfer-Encoding", "transfer-encoding", "Transfer-Encoding is a header MCP needs"},
		{"Host", "host", "Host is a header MCP needs"},
		{"Last-Event-ID", "Last-Event-ID", "Last-Event-Id is a header MCP needs"},
		{"the session", "mcp_session_id", "Mcp-Session-Id is a header MCP needs"},
		{"the protocol version", "MCP-Protocol-Version", "Mcp-Protocol-Version is a header MCP needs"},
		{"the method", "mcp-method", "Mcp-Method is a header MCP needs"},
		{"the name", "Mcp-Name", "Mcp-Name is a header MCP needs"},
		{"a tool parameter", "X-Ok, mcp-param-region", "Mcp-Param-Region is a header MCP needs"},
		{"a pattern", "X-Atlassian-*", `"X-Atlassian-*": exact names only`},
		{"not a header", "X Api Key", `"X Api Key" is not a header name`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, nil, "BYWARD_UPSTREAM_STRIP_HEADERS="+tc.list)
			if err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_STRIP_HEADERS: "+tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	_, _, err := Load(nil, stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`, "BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-Url"), baseFiles)
	if err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_STRIP_HEADERS is set, but a stdio upstream gets no request headers") {
		t.Fatalf("stdio: error %v", err)
	}
}
