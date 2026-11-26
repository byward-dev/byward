package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// Entries of a host list that its check cannot tell apart once folded load, as a warning naming them
// by place, never by value (ADR-0032 R7, ADR-0031 §1): two spellings of one host or origin, and one
// that is the public URL's own, which is always allowed; and client denylist entries with one
// registration key (registration.DenylistKey). Startup, check and doctor warn alike, with
// authentication and without (the denylist is an authenticated setting).
func TestDuplicateHostListEntriesAreAWarningByPlaceAlike(t *testing.T) {
	fake := fixtureEntra(t)
	browser := []string{
		"entries 1 and 2 of 3 name the same host once folded (case, an IP address's spelling, a default port)",
		"entry 3 of 3 is the public URL's host, which is always allowed",
		"entries 1 and 2 of 3 name the same origin once folded (case, an IP address's spelling, a default port)",
		"entry 3 of 3 is the public URL's origin, which is always allowed",
	}
	browserFixes := []string{"BYWARD_ALLOWED_HOSTS: remove one of them", "BYWARD_ALLOWED_HOSTS: remove it", "BYWARD_ALLOWED_ORIGINS: remove one of them", "BYWARD_ALLOWED_ORIGINS: remove it"}
	const denyFolds = "name the same host or client ID once folded (case, a trailing dot, an internationalized host by its xn-- form, an IP address's spelling, a default port, percent-encoding in the path)"
	for _, tc := range []struct {
		name                string
		cfg                 *config.Config
		want, values, fixes []string
	}{
		{"with authentication", loadConfig(t, "https://mcp.example.com/mcp",
			"BYWARD_ALLOWED_HOSTS=A.example,a.example,mcp.example.com:443",
			"BYWARD_ALLOWED_ORIGINS=https://APP.example,https://app.example:443,https://mcp.example.com"),
			browser, []string{"A.example", "APP.example"}, browserFixes},
		// Without authentication the public URL is noAuthEnv's, http://127.0.0.1:8080/mcp, whose host and
		// origin the third entries repeat.
		{"without authentication", loadNoAuthConfig(t, "http://10.0.0.7/mcp",
			"BYWARD_ALLOWED_HOSTS=LocalHost,localhost,127.0.0.1:8080",
			"BYWARD_ALLOWED_ORIGINS=http://LOCALHOST:6274,http://localhost:6274,http://127.0.0.1:8080"),
			browser, []string{"LocalHost", "LOCALHOST"}, browserFixes},
		{"client denylist", loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_CLIENT_DENYLIST=https://127.1/c.json,Deny.Example,https://127.0.0.1/c.json,deny.example."),
			[]string{"entries 1 and 3 of 4 " + denyFolds, "entries 2 and 4 of 4 " + denyFolds},
			// Neither an entry nor its key: deny.example in any case, and any client ID's path.
			[]string{"deny.example", "Deny.Example", "DENY.EXAMPLE", "c.json"}, []string{"BYWARD_CLIENT_DENYLIST: remove one of them"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs logsink.Buffer
			started(t, tc.cfg, logging.New(&logs, "json"))
			warnings, err := checkOffline(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			var check []string
			for _, w := range warnings {
				check = append(check, w.String())
			}
			rep, err := Doctor(context.Background(), tc.cfg, DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}}})
			if err != nil {
				t.Fatal(err)
			}
			var doc []string
			for _, c := range rep.Checks {
				doc = append(doc, c.Message+" ("+c.Fix+")")
			}
			sources := map[string]string{"startup": logs.String(), "check": strings.Join(check, "\n"), "doctor": strings.Join(doc, "\n")}
			for what, text := range sources {
				for _, w := range tc.want {
					if n := strings.Count(text, w); n != 1 {
						t.Errorf("%s warns %q %d times, want once:\n%s", what, w, n, text)
					}
				}
				for _, value := range tc.values {
					if strings.Contains(text, value) {
						t.Errorf("%s shows the value %q:\n%s", what, value, text)
					}
				}
			}
			// The fix names the setting as the operator gave it.
			for _, fix := range tc.fixes {
				if !strings.Contains(sources["doctor"], fix) {
					t.Errorf("doctor does not name the fix %q:\n%s", fix, sources["doctor"])
				}
			}
		})
	}
}
