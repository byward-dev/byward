package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/gate"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// Each gate list the gate itself refuses (config refuses an entry of the wrong form first, #495) is
// refused at startup naming its setting, which proves the wiring maps the gate's error to it; every
// list's mapping is pinned in TestAGateErrorNamesTheSettingOfEachList.
func TestInvalidGateRefusesToStartNamingTheSetting(t *testing.T) {
	for _, setting := range []string{
		"BYWARD_GATE_TENANTS=11111111-1111-4111-8111-111111111111", // the configured tenant is missing
		"BYWARD_GATE_EMAIL_DOMAINS=contoso.example",                // not with Entra
		"BYWARD_GATE_HOSTED_DOMAINS=contoso.example",               // only with Google
	} {
		name, _, _ := strings.Cut(setting, "=")
		t.Run(name, func(t *testing.T) {
			cfg := loadConfig(t, "https://m.example/mcp", setting)
			if _, err := New(cfg, logging.New(io.Discard, "json")); err == nil || !strings.HasPrefix(err.Error(), name+": ") {
				t.Fatalf("err = %v, want it to start with %s", err, name)
			}
		})
	}
}

// A gate list given by flag is named by its flag (#623); the variable rows above are its control.
func TestAnInvalidGateListGivenByFlagIsNamedByItsFlag(t *testing.T) {
	for _, flag := range []string{"--gate-tenants=11111111-1111-4111-8111-111111111111", "--gate-email-domains=contoso.example"} {
		name, _, _ := strings.Cut(flag, "=")
		t.Run(name, func(t *testing.T) {
			cfg, _, err := config.Load([]string{flag}, servedEnv(t), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg, logging.New(io.Discard, "json")); err == nil || !strings.HasPrefix(err.Error(), name+": ") {
				t.Fatalf("err = %v, want it to start with %s", err, name)
			}
		})
	}
}

// gateError names each gate list's error by the setting that fills the list, and any other error as
// the access gate's.
func TestAGateErrorNamesTheSettingOfEachList(t *testing.T) {
	var errs []error
	want := []string{}
	for field, env := range map[string]string{
		gate.FieldTenants: "BYWARD_GATE_TENANTS", gate.FieldRoles: "BYWARD_GATE_ROLES", gate.FieldGroups: "BYWARD_GATE_GROUPS",
		gate.FieldEmailDomains: "BYWARD_GATE_EMAIL_DOMAINS", gate.FieldHostedDomains: "BYWARD_GATE_HOSTED_DOMAINS",
		gate.FieldAllowEmpty: "BYWARD_GATE_ALLOW_EMPTY", gate.FieldAppRoles: "BYWARD_APP_ROLES", gate.FieldAppClientIDs: "BYWARD_APP_CLIENT_IDS",
	} {
		errs = append(errs, &gate.FieldError{Field: field, Msg: "m"})
		want = append(want, env+": m")
	}
	errs = append(errs, errors.New("unknown IdP"))
	want = append(want, "access gate: unknown IdP")
	if got := gateError(loadConfig(t, "https://m.example/mcp"), errors.Join(errs...)).Error(); got != strings.Join(want, "; ") {
		t.Fatalf("got  %s\nwant %s", got, strings.Join(want, "; "))
	}
}

func TestEveryInvalidGateListIsReported(t *testing.T) {
	cfg := loadConfig(t, "https://m.example/mcp", "BYWARD_GATE_EMAIL_DOMAINS=contoso.example", "BYWARD_GATE_HOSTED_DOMAINS=contoso.example")
	_, err := New(cfg, logging.New(io.Discard, "json"))
	if err == nil || !strings.Contains(err.Error(), "BYWARD_GATE_EMAIL_DOMAINS: ") || !strings.Contains(err.Error(), "; BYWARD_GATE_HOSTED_DOMAINS: ") {
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
			cfg := loadConfig(t, "https://m.example/mcp", tc.extra...)
			var buf bytes.Buffer
			if _, err := New(cfg, logging.New(&buf, "json")); err != nil {
				t.Fatal(err)
			}
			warnings := 0
			for _, m := range logsink.Records[struct{ Level, Msg string }](t, buf.String()) {
				if m.Level == "WARN" && strings.HasPrefix(m.Msg, "access gate is empty") {
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
	cfg := loadConfig(t, "https://m.example/mcp", "BYWARD_GATE_ROLES=MCP.User")
	srv, err := New(cfg, logging.New(io.Discard, "json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Gate == nil || got.Audit == nil || got.ObserveIdP == nil || got.IdPName != "entra" {
		t.Fatalf("broker wired without its gate, audit log or IdP observation: gate %v, audit %v, IdP %q", got.Gate, got.Audit, got.IdPName)
	}
	got.ObserveIdP("callback", "success", time.Millisecond)
	metrics := internalMetrics(t, srv.Internal.Handler)
	if !regexp.MustCompile(`\{[^}]*idp="entra"[^}]*operation="callback"[^}]*outcome="success"`).MatchString(metrics) {
		t.Fatalf("an IdP observation did not reach /metrics as idp=entra, callback, success:\n%s", metrics)
	}
	if got.ObserveIdPAlert == nil {
		t.Fatal("broker wired without IdP alert observation")
	}
	// Before any alert every series is exported at 0, so an increase() rule sees the first; without
	// On-Behalf-Of there is no on_behalf_of series.
	for _, op := range broker.IdPOperations {
		for _, a := range idp.Alerts {
			if s := `byward_idp_alerts_total{idp="entra",operation="` + op + `",reason="` + string(a) + `"} 0`; !strings.Contains(metrics, s) {
				t.Errorf("%s is not exported before any alert:\n%s", s, metrics)
			}
		}
	}
	if strings.Contains(metrics, `operation="on_behalf_of"`) {
		t.Errorf("an on_behalf_of alert series is exported without On-Behalf-Of:\n%s", metrics)
	}
	series := `byward_idp_alerts_total{idp="entra",operation="refresh",reason="credential_rejected"} `
	got.ObserveIdPAlert("refresh", "credential_rejected")
	metrics = internalMetrics(t, srv.Internal.Handler)
	if want := series + "1"; !strings.Contains(metrics, want) {
		t.Fatalf("an IdP alert did not reach /metrics as %s:\n%s", want, metrics)
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

// Every gate list is named by a setting the registry holds, so naming it in a refusal cannot panic:
// NameAsGiven panics on an unknown name, and the refusal is the only place it is read.
func TestEveryGateListIsNamedByARegisteredSetting(t *testing.T) {
	for field, name := range gateSettings {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("gate list %s: setting %q: %v", field, name, r)
				}
			}()
			(*config.Values)(nil).NameAsGiven(name)
		}()
	}
}
