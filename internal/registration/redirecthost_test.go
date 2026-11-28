package registration

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
)

// Each way a client gets its redirect URIs applies the host rule (#707) as ADR-0009 says for that
// way: a new DCR registration keeps the URIs that pass (its 2026-11-06 amendment); a stored DCR
// registration is checked again on every lookup, so one holding a URI the rule now refuses is an
// unknown client, which registers again; a CIMD document, which the proxy does not own, is refused
// whole; and a static client stops the configuration from loading, naming the URI as logs may and
// the rule it breaks.
func TestEachRegistrationPathAppliesTheRedirectHostRule(t *testing.T) {
	const refusedHost, refusedPort = "https://bücher.example/cb", "http://127.0.0.1:0/cb"
	const shownHost = "https://b%C3%BCcher.example/cb" // as logs may show it (logging.URL)
	hostText, portText := reasonText[ReasonHost], reasonText[ReasonPort]

	t.Run("a new DCR registration keeps the URIs that pass", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{"client_name": "App", "redirect_uris": []string{refusedHost, refusedPort, "https://app.example/cb"}})
		if err != nil {
			t.Fatal(err)
		}
		reg, err := newDCR(memory.New(), newClock().Now, 0).Register(context.Background(), body)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := stringsOf(response(t, reg)["redirect_uris"]), []string{"https://app.example/cb"}; !slices.Equal(got, want) {
			t.Errorf("registered %q, want %q", got, want)
		}
		if want := []string{shownHost, refusedPort}; !slices.Equal(reg.Dropped, want) {
			t.Errorf("dropped %q, want %q", reg.Dropped, want)
		}
	})

	t.Run("a new DCR registration with no URI that passes is refused", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{"client_name": "App", "redirect_uris": []string{refusedHost, refusedPort}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newDCR(memory.New(), newClock().Now, 0).Register(context.Background(), body); !errors.Is(err, ErrInvalidRedirectURI) {
			t.Errorf("err = %v, want ErrInvalidRedirectURI", err)
		}
	})

	t.Run("a stored DCR registration holding a refused URI is an unknown client", func(t *testing.T) {
		c := newClock()
		for uri, want := range map[string]string{refusedHost: "redirect URI " + shownHost + " rejected: " + hostText, refusedPort: "redirect URI " + refusedPort + " rejected: " + portText} {
			meta, err := json.Marshal(map[string]any{"client_name": "App", "redirect_uris": []string{"https://app.example/cb", uri}})
			if err != nil {
				t.Fatal(err)
			}
			st := memory.New()
			rec := store.Client{ID: DCRIDPrefix + "stored", Metadata: meta, CreatedAt: c.Now().Add(-time.Hour), ExpiresAt: c.Now().Add(time.Hour)}
			if err := st.CreateClient(context.Background(), rec, 10); err != nil {
				t.Fatal(err)
			}
			_, err = newDCR(st, c.Now, 0).Client(context.Background(), rec.ID)
			if !errors.Is(err, ErrUnknownClient) || !strings.Contains(err.Error(), "stored registration: redirect_uris[1]: "+want) {
				t.Errorf("%s: err = %v, want an unknown client naming %q", uri, err, want)
			}
		}
	})

	t.Run("a CIMD document with one refused URI is refused whole", func(t *testing.T) {
		for uri, want := range map[string]string{refusedHost: "redirect URI " + shownHost + " rejected: " + hostText, refusedPort: "redirect URI " + refusedPort + " rejected: " + portText} {
			m, err := parseCIMD(cimdID, doc(map[string]any{"redirect_uris": []string{"https://app.example/cb", uri}}))
			if m != nil || err == nil || !strings.Contains(err.Error(), "redirect_uris[1]: "+want) {
				t.Errorf("%s: %v, %v; want the document refused, naming %q", uri, m, err, want)
			}
		}
	})

	t.Run("a static client with a refused URI stops the configuration loading", func(t *testing.T) {
		for uri, want := range map[string]string{refusedHost: "redirect URI " + shownHost + " rejected: " + hostText, refusedPort: "redirect URI " + refusedPort + " rejected: " + portText} {
			_, err := load(t, files{"/etc/mcp/clients.json": `{"clients":[{"client_id":"a","token_endpoint_auth_method":"none","redirect_uris":["https://app.example/cb","` + uri + `"]}]}`})
			if err == nil || !strings.Contains(err.Error(), "redirect_uris[1]: "+want) {
				t.Errorf("%s: %v, want it refused, naming %q", uri, err, want)
			}
		}
	})
}
