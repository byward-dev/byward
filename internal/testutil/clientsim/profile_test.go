package clientsim

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/clientdocs"
)

// A profile is evidence, not a wish list: each one names its version and matrix cell, every fact has
// a source or says it is assumed, and a CIMD profile's redirect is one its published document lists.
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
			if p.Registration != CIMD {
				return
			}
			var doc struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			if err := json.Unmarshal(clientdocs.Load(t, p.Document).Body, &doc); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(doc.RedirectURIs, p.RedirectURI) {
				t.Fatalf("redirect %s is not in the client's published document %v", p.RedirectURI, doc.RedirectURIs)
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

// recorder is a testing.TB that records a failure instead of failing the test.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper()               {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true; runtime.Goexit() }

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
			r := &recorder{TB: t}
			done := make(chan struct{})
			go func() { defer close(done); WantNoAuthLoop(r, tc.p, &http.Response{StatusCode: tc.status}) }()
			<-done
			if r.failed != tc.fails {
				t.Fatalf("failed = %v, want %v", r.failed, tc.fails)
			}
		})
	}
}
