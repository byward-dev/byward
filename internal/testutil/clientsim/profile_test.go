package clientsim

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/recordtb"
)

// A profile is evidence, not a wish list: each one names its version and matrix cell, every fact has
// a source or says it is assumed, and a CIMD or DCR profile's redirect is one the broker accepts
// against its published document or registration request.
func TestEveryProfileIsSourcedAndMatchesItsClientsDocument(t *testing.T) {
	cells := map[string]bool{}
	for _, p := range All {
		t.Run(p.Cell, func(t *testing.T) {
			if p.Client == "" || p.Version == "" || p.Cell == "" || p.RedirectURI == "" || len(p.Discovery) == 0 {
				t.Fatalf("incomplete profile: %+v", p)
			}
			if cells[p.Cell] {
				t.Fatalf("two profiles for cell %q", p.Cell)
			}
			cells[p.Cell] = true
			if len(p.Facts) == 0 {
				t.Fatal("no facts: a profile must say where its behaviour comes from")
			}
			for _, f := range p.Facts {
				if f.What == "" || f.Source == "" {
					t.Errorf("fact %+v has no source; write %q if nobody has checked it", f, Assumed)
				}
			}
			var body []byte
			switch p.Registration {
			case CIMD:
				body = clientdocs.Load(t, p.Document).Body
			case DCR:
				reg := clientdocs.LoadRegistration(t, p.Document)
				if body = reg.Body; reg.Redirect != p.RedirectURI {
					t.Fatalf("redirect %s is not the fixture's sign-in redirect %s", p.RedirectURI, reg.Redirect)
				}
			default:
				return
			}
			var doc struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			if err := registration.MatchRedirect(doc.RedirectURIs, p.RedirectURI); err != nil { // the broker's rule: any loopback port
				t.Fatalf("the broker refuses redirect %s against the client's document or registration request %v: %v", p.RedirectURI, doc.RedirectURIs, err)
			}
		})
	}
}

// docs/quality-lenses.md lists the cells the simulator covers: every profile's cell is a "simulated"
// row there, and every "simulated" row has a profile, so the table promises nothing untested.
func TestTheMatrixDocAndTheProfilesNameTheSameSimulatedCells(t *testing.T) {
	b, err := os.ReadFile("../../../docs/quality-lenses.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		cols := strings.Split(line, "|")
		if len(cols) == 5 && strings.HasPrefix(strings.TrimSpace(cols[3]), "simulated") {
			documented[strings.TrimSpace(cols[1])] = true
		}
	}
	profiled := map[string]bool{}
	for _, p := range All {
		profiled[p.Cell] = true
		if !documented[p.Cell] {
			t.Errorf("docs/quality-lenses.md has no simulated row for the profile's cell %q", p.Cell)
		}
	}
	for cell := range documented {
		if !profiled[cell] {
			t.Errorf("docs/quality-lenses.md marks %q simulated, but no profile covers it", cell)
		}
	}
}

// WantNoAuthLoop fails exactly on the answers that would make the client sign in again.
func TestWantNoAuthLoopFailsOnTheAnswersThatLoopTheClient(t *testing.T) {
	treats, ignores := Profile{Client: "a", Treats403AsAuthFailure: true}, Profile{Client: "b"}
	for _, tc := range []struct {
		name   string
		p      Profile
		status int
		fails  bool
	}{
		{"200", treats, http.StatusOK, false},
		{"403 to a client that treats it as an auth failure", treats, http.StatusForbidden, true},
		{"403 to a client that does not", ignores, http.StatusForbidden, false},
		{"401 to any client", ignores, http.StatusUnauthorized, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := recordtb.Run(t, func(tb testing.TB) { WantNoAuthLoop(tb, tc.p, &http.Response{StatusCode: tc.status}) })
			fatals := 0 // a failing answer is one fatal and no error: the check stops there
			if tc.fails {
				fatals = 1
			}
			if len(rep.Errors) != 0 || len(rep.Fatals) != fatals {
				t.Fatalf("errors %q, fatals %q; want no error and %d fatal", rep.Errors, rep.Fatals, fatals)
			}
		})
	}
}
