package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// roleGate allows users with role and refuses others with a Denial.
type roleGate struct{ role string }

type denial struct{}

func (denial) Error() string      { return "access gate: denied" }
func (denial) DeniedRule() string { return "role" }

func (g roleGate) Allow(_ context.Context, id idp.Identity) error {
	for _, r := range id.Roles {
		if r == g.role {
			return nil
		}
	}
	return denial{}
}

// brokenGate fails to decide, as a gate doing I/O might.
type brokenGate struct{}

func (brokenGate) Allow(context.Context, idp.Identity) error {
	return errors.New("directory lookup timed out")
}

func (e *env) callback(t *testing.T) (*http.Response, string, int) {
	t.Helper()
	c, cb := e.startLogin(t, nil)
	res := e.do(t, "GET", "/callback/entra?"+cb.RawQuery, nil, []*http.Cookie{c})
	body, _ := io.ReadAll(res.Body)
	return res, string(body), len(e.st.GrantIDs())
}

// The access gate runs in the callback, before any grant exists (ADR-0015 §1-2).
func TestGateDecidesAtTheCallbackBeforeAnyGrant(t *testing.T) {
	for name, tc := range map[string]struct {
		roles   []string
		allowed bool
	}{
		"user with the role":    {roles: []string{"MCP.User"}, allowed: true},
		"user without the role": {},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.Gate = roleGate{"MCP.User"} })
			e.fake.Set(fakeidp.WithUser(fakeidp.User{Roles: tc.roles}))
			res, body, grants := e.callback(t)
			if tc.allowed {
				if res.StatusCode != http.StatusFound || grants != 1 {
					t.Fatalf("status %d, grants %d", res.StatusCode, grants)
				}
				return
			}
			// A browser page, never parsed by the MCP client, so 403 (ADR-0015 §2, clarified).
			if res.StatusCode != http.StatusForbidden || res.Header.Get("Location") != "" || grants != 0 {
				t.Fatalf("denied user: status %d, Location %q, grants %d", res.StatusCode, res.Header.Get("Location"), grants)
			}
			if !strings.Contains(body, "have access to this server") || !strings.Contains(body, "Ask your operator") {
				t.Fatalf("denial page = %s", body)
			}
		})
	}
}

// A denial is one access_denied audit event naming the rule, with pseudonymous keys only (ADR-0015 §5).
func TestGateDenialIsAuditedWithTheRuleAndNoName(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Gate = roleGate{"MCP.User"} })
	if res, _, _ := e.callback(t); res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", res.StatusCode)
	}
	u := e.fake.User()
	rec := e.oneAuditEvent(t, "access_denied", map[string]any{"outcome": "failure", "level": "WARN", "reason": "role",
		"user_key": e.fake.TenantID() + ":" + u.OID, "client_id": clientID, "idp": "entra", "request_id": "*"})
	for k, v := range rec {
		if s, _ := v.(string); strings.Contains(s, u.PreferredUsername) || strings.Contains(s, u.Name) {
			t.Fatalf("audit field %s carries the user's name: %v", k, v)
		}
	}
	if logins := e.auditEvents(t, "login"); len(logins) != 0 {
		t.Errorf("a denied user was also audited as a login: %v", logins)
	}
}

func TestGateFailureIsAServerErrorNotADenial(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Gate = brokenGate{} })
	res, body, grants := e.callback(t)
	if res.StatusCode != http.StatusInternalServerError || grants != 0 || strings.Contains(body, "have access to this server") {
		t.Fatalf("status %d, grants %d, body %s", res.StatusCode, grants, body)
	}
	if denied := e.auditEvents(t, "access_denied"); len(denied) != 0 {
		t.Fatalf("a gate failure was audited as a denial: %v", denied)
	}
}
