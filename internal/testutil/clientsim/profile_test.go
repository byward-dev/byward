package clientsim

import (
	"encoding/json"
	"os"
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
			if err := json.Unmarshal(clientdocs.Load(t, p.ClientID).Body, &doc); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(doc.RedirectURIs, p.RedirectURI) {
				t.Fatalf("redirect %s is not in the client's published document %v", p.RedirectURI, doc.RedirectURIs)
			}
		})
	}
}

// docs/quality-lenses.md lists the cells the simulator covers; the list and the profiles agree.
func TestTheMatrixDocNamesEverySimulatedCell(t *testing.T) {
	b, err := os.ReadFile("../../../docs/quality-lenses.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range All {
		if !strings.Contains(string(b), p.Cell) {
			t.Errorf("docs/quality-lenses.md does not name the simulated cell %q", p.Cell)
		}
	}
}
