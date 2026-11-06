package audit

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// Set BYWARD_UPDATE_GOLDEN=1 to rewrite testdata/events.golden.jsonl after an intended
// schema change (and bump SchemaVersion if the change is incompatible).
const golden = "testdata/events.golden.jsonl"

var timestamp = regexp.MustCompile(`"time":"[^"]*"`)

// samples is one record per event, with the fields its call sites set.
var samples = []Event{
	{Name: Login, Outcome: Success, ClientID: "client-1", UserKey: "tid:oid", GrantID: "grant-1", IdP: "entra"},
	{Name: Login, Outcome: Failure, Reason: "the IdP refused the sign-in", ClientID: "client-1", IdP: "entra"},
	{Name: AccessDenied, Outcome: Failure, Reason: "not allowed by the access gate", ClientID: "client-1", UserKey: "tid:oid", IdP: "entra"},
	{Name: TokenIssued, Outcome: Success, ClientID: "client-1", UserKey: "tid:oid", GrantID: "grant-1"},
	{Name: TokenRejected, Outcome: Failure, Reason: "invalid_grant", ClientID: "client-1"},
	{Name: AccessTokenRejected, Outcome: Failure, Reason: "invalid_token"},
	{Name: GrantRevoked, Outcome: Success, Reason: "authorization code reused", ClientID: "client-1", GrantID: "grant-1"},
	{Name: ClientRegistered, Outcome: Success, Reason: "static", ClientID: "client-1"},
	{Name: KeyLoaded, Outcome: Success, Reason: "signing", KeyID: "k1"},
	{Name: HostRejected, Outcome: Failure, Host: "evil.example"},
	{Name: OriginRejected, Outcome: Failure, Origin: "https://evil.example"},
	{Name: ConsentShown, Outcome: Success, ClientID: "client-1", ClientTrust: "verified"},
	{Name: ConsentGranted, Outcome: Success, ClientID: "client-1", ClientTrust: "verified"},
	{Name: ConsentDenied, Outcome: Failure, Reason: "the user denied the request", ClientID: "client-1", ClientTrust: "verified"},
	{Name: RateLimited, Outcome: Failure, Reason: "authorize"},
	{Name: StoreRestored, Outcome: Success, Reason: "restored from an older copy", Epoch: 2},
	{Name: SessionRejected, Outcome: Failure, Reason: "session of another user", UserKey: "tid:oid"},
}

func render(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	l := New(logging.New(&buf, "json"), nil, time.Now)
	for _, e := range samples {
		r := httptest.NewRequest("GET", "/mcp", nil)
		r.RemoteAddr = "192.0.2.7:1234"
		switch e.Name {
		case AccessTokenRejected, HostRejected, OriginRejected, TokenRejected, ConsentShown, ConsentGranted, ConsentDenied, RateLimited:
			l.RecordUnauthenticated(r, e)
		case ClientRegistered, KeyLoaded, StoreRestored:
			l.Record(nil, e) // startup: no request
		default:
			l.Record(r, e)
		}
	}
	return timestamp.ReplaceAllString(buf.String(), `"time":"T"`)
}

func TestAuditRecordsMatchTheGoldenSchema(t *testing.T) {
	got := render(t)
	if os.Getenv("BYWARD_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("audit records changed (public interface, ADR-0023); if intended, rerun with BYWARD_UPDATE_GOLDEN=1 and update docs/reference/observability.md\ngot:\n%s\nwant:\n%s", got, want)
	}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		event, _ := rec["event"].(string)
		outcome, _ := rec["outcome"].(string)
		if rec["log.type"] != "audit" || rec["schema_version"] != float64(SchemaVersion) || event == "" || outcome == "" {
			t.Fatalf("record lacks log.type, schema_version, event or outcome: %s", line)
		}
	}
}

// names lists every event constant; a new one must be added here, to samples and to the docs.
var names = []string{Login, AccessDenied, TokenIssued, TokenRejected, AccessTokenRejected, GrantRevoked,
	ClientRegistered, KeyLoaded, HostRejected, OriginRejected, ConsentShown, ConsentGranted, ConsentDenied, RateLimited, StoreRestored, SessionRejected}

func TestEveryEventHasASampleAndADocsRow(t *testing.T) {
	docs, err := os.ReadFile("../../docs/reference/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		found := false
		for _, s := range samples {
			found = found || s.Name == n
		}
		if !found {
			t.Errorf("event %q has no golden sample", n)
		}
		if !strings.Contains(string(docs), "| `"+n+"` |") {
			t.Errorf("event %q has no row in docs/reference/observability.md", n)
		}
	}
}

// Users behind one NAT share a source address; many page views must not hide their decisions, and
// one source's flood must not hide another source's records.
func TestRecordsAreLimitedPerSourceAndEvent(t *testing.T) {
	var buf bytes.Buffer
	now := time.Unix(1_800_000_000, 0)
	l := New(logging.New(&buf, "json"), nil, func() time.Time { return now })
	nat := httptest.NewRequest("GET", "/authorize", nil)
	nat.RemoteAddr = "192.0.2.7:1234"
	for range unauthBurst + 5 {
		l.RecordUnauthenticated(nat, Event{Name: ConsentShown, Outcome: Success, ClientID: "client-1"})
	}
	other := httptest.NewRequest("GET", "/authorize", nil)
	other.RemoteAddr = "198.51.100.9:1"
	l.RecordUnauthenticated(other, Event{Name: ConsentShown, Outcome: Success, ClientID: "client-1"})
	l.RecordUnauthenticated(nat, Event{Name: ConsentDenied, Outcome: Failure, ClientID: "client-1"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if n := strings.Count(buf.String(), `"event":"consent_shown","outcome":"success","client_id":"client-1","remote_ip":"192.0.2.7"`); n != unauthBurst {
		t.Fatalf("logged %d consent_shown records from the flooding source, want %d", n, unauthBurst)
	}
	if len(lines) != unauthBurst+2 {
		t.Fatalf("logged %d records, want %d: %s", len(lines), unauthBurst+2, buf.String())
	}
	for _, want := range []string{`"remote_ip":"198.51.100.9"`, `"event":"consent_denied"`} {
		var line string
		for _, l := range lines {
			if strings.Contains(l, want) {
				line = l
			}
		}
		if line == "" || strings.Contains(line, "suppressed") {
			t.Fatalf("record with %s missing or marked suppressed: %q", want, line)
		}
	}
}

func TestUnauthenticatedEventsAreRateLimitedPerSourceAndCountedAnyway(t *testing.T) {
	var buf bytes.Buffer
	counted := 0
	now := time.Unix(1_800_000_000, 0)
	l := New(logging.New(&buf, "json"), func(string, string) { counted++ }, func() time.Time { return now })
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.RemoteAddr = "192.0.2.7:1234"
	for range unauthBurst + 5 {
		l.RecordUnauthenticated(r, Event{Name: HostRejected, Outcome: Failure, Host: "evil.example"})
	}
	if n := strings.Count(buf.String(), "\n"); n != unauthBurst {
		t.Fatalf("logged %d records, want %d", n, unauthBurst)
	}
	if counted != unauthBurst+5 {
		t.Fatalf("observer saw %d events, want %d (suppressed ones count too)", counted, unauthBurst+5)
	}
	now = now.Add(unauthWindow)
	buf.Reset()
	l.RecordUnauthenticated(r, Event{Name: HostRejected, Outcome: Failure, Host: "evil.example"})
	if !strings.Contains(buf.String(), `"suppressed":5`) {
		t.Fatalf("the next record does not report suppressed=5: %s", buf.String())
	}
}

func TestNilLogIsSafeToCall(t *testing.T) {
	var l *Log
	l.Record(nil, Event{Name: Login, Outcome: Success})
	l.RecordUnauthenticated(httptest.NewRequest("GET", "/", nil), Event{Name: HostRejected, Outcome: Failure})
}
