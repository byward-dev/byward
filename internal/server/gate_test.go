package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
)

func gateEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return append(append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), extra...)
}

// One case per gate list: the error names the exact setting, which proves the wiring maps each
// list to its own setting. The gate's own rules are tested in internal/gate.
func TestInvalidGateRefusesToStartNamingTheSetting(t *testing.T) {
	for _, setting := range []string{
		"BYWARD_GATE_TENANTS=11111111-1111-4111-8111-111111111111", // the configured tenant is missing
		"BYWARD_GATE_ROLES=a\x7fb",
		"BYWARD_GATE_GROUPS=mcp-users",
		"BYWARD_GATE_EMAIL_DOMAINS=contoso.example",
		"BYWARD_GATE_HOSTED_DOMAINS=contoso.example",
	} {
		name, _, _ := strings.Cut(setting, "=")
		t.Run(name, func(t *testing.T) {
			cfg, _, err := config.Load(nil, gateEnv(t, setting), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg, logging.New(io.Discard, "json")); err == nil || !strings.HasPrefix(err.Error(), name+": ") {
				t.Fatalf("err = %v, want it to start with %s", err, name)
			}
		})
	}
}

func TestEveryInvalidGateListIsReported(t *testing.T) {
	cfg, _, err := config.Load(nil, gateEnv(t, "BYWARD_GATE_GROUPS=mcp-users", "BYWARD_GATE_EMAIL_DOMAINS=contoso.example"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(cfg, logging.New(io.Discard, "json"))
	if err == nil || !strings.Contains(err.Error(), "BYWARD_GATE_GROUPS: ") || !strings.Contains(err.Error(), "; BYWARD_GATE_EMAIL_DOMAINS: ") {
		t.Fatalf("err = %v, want both settings named", err)
	}
}

func TestOnlyAnEmptyGateWarnsAtStartup(t *testing.T) {
	for name, tc := range map[string]struct {
		extra []string
		warn  bool
	}{
		"empty":     {warn: true},
		"with role": {extra: []string{"BYWARD_GATE_ROLES=MCP.User"}},
		// The configured tenant reaches the gate, so listing it is accepted.
		"own tenant": {extra: []string{"BYWARD_GATE_TENANTS=" + fixtureTenant}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := config.Load(nil, gateEnv(t, tc.extra...), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if _, err := New(cfg, logging.New(&buf, "json")); err != nil {
				t.Fatal(err)
			}
			warnings := 0
			sc := bufio.NewScanner(&buf)
			for sc.Scan() {
				var m map[string]any
				if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
					t.Fatalf("log line %q: %v", sc.Text(), err)
				}
				if msg, _ := m["msg"].(string); m["level"] == "WARN" && strings.HasPrefix(msg, "access gate is empty") {
					warnings++
				}
			}
			if (warnings == 1) != tc.warn || warnings > 1 {
				t.Fatalf("empty-gate warnings = %d, want warn %v", warnings, tc.warn)
			}
		})
	}
}

// The configured gate reaches the broker (without it the broker would fall back to AllowAll), next
// to the audit log and IdP observation, which a nil value would silently discard.
func TestWiredBrokerGetsTheConfiguredGateAndObservability(t *testing.T) {
	got := captureBroker(t, nil)
	cfg, _, err := config.Load(nil, gateEnv(t, "BYWARD_GATE_ROLES=MCP.User"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, logging.New(io.Discard, "json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Gate == nil || got.Audit == nil || got.ObserveIdP == nil || got.IdPName != "entra" {
		t.Fatalf("broker wired without its gate, audit log or IdP observation: gate %v, audit %v, IdP %q", got.Gate, got.Audit, got.IdPName)
	}
	got.ObserveIdP("callback", "success", time.Millisecond)
	rec := httptest.NewRecorder()
	srv.Internal.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "http://127.0.0.1:9090/metrics", nil))
	if !regexp.MustCompile(`\{[^}]*idp="entra"[^}]*operation="callback"[^}]*outcome="success"`).MatchString(rec.Body.String()) {
		t.Fatalf("an IdP observation did not reach /metrics as idp=entra, callback, success:\n%s", rec.Body.String())
	}
	if got.ObserveIdPAlert == nil {
		t.Fatal("broker wired without IdP alert observation")
	}
	// Before any alert every series is exported at 0, so an increase() rule sees the first; without
	// On-Behalf-Of there is no on_behalf_of series.
	for _, op := range broker.IdPOperations {
		for _, a := range idp.Alerts {
			if s := `byward_idp_alerts_total{idp="entra",operation="` + op + `",reason="` + string(a) + `"} 0`; !strings.Contains(rec.Body.String(), s) {
				t.Errorf("%s is not exported before any alert:\n%s", s, rec.Body.String())
			}
		}
	}
	if strings.Contains(rec.Body.String(), `operation="on_behalf_of"`) {
		t.Errorf("an on_behalf_of alert series is exported without On-Behalf-Of:\n%s", rec.Body.String())
	}
	series := `byward_idp_alerts_total{idp="entra",operation="refresh",reason="credential_rejected"} `
	got.ObserveIdPAlert("refresh", "credential_rejected")
	rec = httptest.NewRecorder()
	srv.Internal.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "http://127.0.0.1:9090/metrics", nil))
	if want := series + "1"; !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("an IdP alert did not reach /metrics as %s:\n%s", want, rec.Body.String())
	}
	id := idp.Identity{Subject: fixtureTenant + ":x", Claims: map[string]any{"tid": fixtureTenant}}
	var d broker.Denial
	if err := got.Gate.Allow(context.Background(), id); !errors.As(err, &d) || d.DeniedRule() != "role" {
		t.Fatalf("user without the role: %v", err)
	}
	id.Roles = []string{"MCP.User"}
	if err := got.Gate.Allow(context.Background(), id); err != nil {
		t.Fatalf("user with the role: %v", err)
	}
}
