package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func runWith(args []string, env ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, env, &out, &errb)
	return code, out.String(), errb.String()
}

func TestConfigErrorExitCode(t *testing.T) {
	code, _, stderr := runWith(nil, "MCP_AUTHPROXY_PUBLC_URL=x")
	if code != exitConfig || !strings.Contains(stderr, "did you mean MCP_AUTHPROXY_PUBLIC_URL?") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestHelp(t *testing.T) {
	code, stdout, _ := runWith([]string{"--help"})
	if code != exitOK || !strings.Contains(stdout, "MCP_AUTHPROXY_UPSTREAM_URL") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	code, stdout, _ := runWith([]string{"--version", "--json"})
	var v version
	if code != exitOK || json.Unmarshal([]byte(stdout), &v) != nil || v.GoVersion == "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestPrintConfigShowsSources(t *testing.T) {
	code, stdout, _ := runWith([]string{"--print-config", "--listen", "127.0.0.1:9"},
		"MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp")
	for _, want := range []string{"MCP_AUTHPROXY_LISTEN=127.0.0.1:9 (flag)", "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp (env)", "MCP_AUTHPROXY_SCOPE=mcp (default)"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("code=%d missing %q in %q", code, want, stdout)
		}
	}
}

func TestRunStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, nil, []string{"MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN=127.0.0.1:0"}, &out, &errb)
	if code != exitOK || !strings.Contains(errb.String(), `"msg":"config"`) {
		t.Fatalf("code=%d logs=%s", code, errb.String())
	}
}
