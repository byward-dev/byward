package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/golden"
)

// Set BYWARD_UPDATE_GOLDEN=1 to rewrite testdata/events.golden.jsonl after an intended
// schema change (and bump SchemaVersion if the change is incompatible).
const eventsGolden = "testdata/events.golden.jsonl"

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
	{Name: ConsentRemembered, Outcome: Success, ClientID: "client-1", ClientTrust: "verified", UserKey: "tid:oid", GrantID: "grant-1", IdP: "entra"},
	{Name: ConsentRemembered, Outcome: Failure, Reason: "user_mismatch", ClientID: "client-1", UserKey: "tid:oid", IdP: "entra"},
	{Name: ConsentSilent, Outcome: Failure, Reason: "consent_required", ClientID: "client-1", ClientTrust: "domain", IdP: "entra"},
	{Name: RateLimited, Outcome: Failure, Reason: "authorize"},
	{Name: StoreRestored, Outcome: Success, Reason: "restored from an older copy", Epoch: 2},
	{Name: SessionRejected, Outcome: Failure, Reason: "session of another user", UserKey: "tid:oid"},
	{Name: ProcessEvicted, Outcome: Success, Reason: "user_cap", UserKey: "tid:oid"},
	{Name: ProcessEvicted, Outcome: Success, Reason: "upstream_cap", UserKey: "tid:oid", OpenStreams: 1},
	{Name: DownstreamTokenRefused, Outcome: Failure, Reason: "consent_required", ClientID: "client-1", UserKey: "tid:oid", GrantID: "grant-1", IdP: "entra"},
	{Name: AppTokenAccepted, Outcome: Success, ClientID: "app-client-1", UserKey: "tid:app-oid", IdP: "entra"},
	{Name: AppTokenRejected, Outcome: Failure, Reason: "denied_role", ClientID: "app-client-1", UserKey: "tid:app-oid", IdP: "entra"},
}

func render(t *testing.T) string {
	t.Helper()
	l, buf, _ := stoppedClockLog(nil) // each sample once: well under the burst
	for _, e := range samples {
		r := from("192.0.2.7:1234")
		switch e.Name {
		case AccessTokenRejected, AppTokenRejected, HostRejected, OriginRejected, TokenRejected, ConsentShown, ConsentGranted, ConsentDenied, RateLimited:
			l.RecordUnauthenticated(r, e)
		case ClientRegistered, KeyLoaded, StoreRestored, ProcessEvicted:
			l.Record(nil, e) // startup, or no request of the user's
		default:
			l.Record(r, e)
		}
	}
	return timestamp.ReplaceAllString(buf.String(), `"time":"T"`)
}

func TestAuditRecordsMatchTheGoldenSchema(t *testing.T) {
	got := render(t)
	golden.Check(t, eventsGolden, got, "the audit records are a public interface (ADR-0023): update docs/reference/observability.md too")
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

// eventNames are the values of the "Event names" constants in audit.go, read from the source so a
// new event cannot be left out of the checks below.
func eventNames(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "audit.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST || g.Doc == nil || !strings.HasPrefix(g.Doc.Text(), "Event names.") {
			continue
		}
		for _, spec := range g.Specs {
			for _, v := range spec.(*ast.ValueSpec).Values {
				lit, ok := v.(*ast.BasicLit)
				n, err := "", errors.New("not a string literal")
				if ok {
					n, err = strconv.Unquote(lit.Value)
				}
				if err != nil {
					t.Fatalf("an event name in audit.go is not a plain string: %v", err)
				}
				names = append(names, n)
			}
		}
	}
	if len(names) < 20 {
		t.Fatalf("found %d event names in audit.go; the Event names block moved?", len(names))
	}
	return names
}

func TestEveryEventHasAGoldenSample(t *testing.T) {
	for _, n := range eventNames(t) {
		found := false
		for _, s := range samples {
			found = found || s.Name == n
		}
		if !found {
			t.Errorf("event %q has no golden sample", n)
		}
	}
}

// A flood of one event and outcome from a source never hides that source's next record of another
// event or outcome: an open /register is an abuse path whose refusals an operator looks for, users
// behind one NAT share a source, and one refusal must not mask another.
func TestAFloodOfOneEventAndOutcomeNeverHidesAnother(t *testing.T) {
	for name, tc := range map[string]struct{ flood, next Event }{
		"successes never hide refusals": {
			Event{Name: ClientRegistered, Outcome: Success, Reason: "dcr", ClientID: "dcr-x"},
			Event{Name: ClientRegistered, Outcome: Failure, Reason: "rate_limited"}},
		"page views never hide decisions": {
			Event{Name: ConsentShown, Outcome: Success, ClientID: "client-1"},
			Event{Name: ConsentDenied, Outcome: Failure, ClientID: "client-1"}},
		"one refusal never hides another": {
			Event{Name: HostRejected, Outcome: Failure, Host: "evil.example"},
			Event{Name: OriginRejected, Outcome: Failure, Origin: "https://evil.example"}},
	} {
		t.Run(name, func(t *testing.T) {
			l, buf, _ := stoppedClockLog(nil)
			r := from("192.0.2.7:1234")
			for range unauthBurst + 5 {
				l.RecordUnauthenticated(r, tc.flood)
			}
			flooded := `"event":"` + tc.flood.Name + `","outcome":"` + tc.flood.Outcome + `"`
			if n := strings.Count(buf.String(), flooded); n != unauthBurst {
				t.Fatalf("logged %d flood records, want %d (the flood must exhaust its budget):\n%s", n, unauthBurst, buf.String())
			}
			l.RecordUnauthenticated(r, tc.next)
			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			last := lines[len(lines)-1]
			if want := `"event":"` + tc.next.Name + `","outcome":"` + tc.next.Outcome + `"`; !strings.Contains(last, want) {
				t.Fatalf("the %s/%s record was dropped; last line: %s", tc.next.Name, tc.next.Outcome, last)
			}
			if strings.Contains(last, "suppressed") {
				t.Fatalf("the %s/%s record carries the flood's suppressed count: %s", tc.next.Name, tc.next.Outcome, last)
			}
		})
	}
}

// One source's flood never hides another source's records: another IPv4 address, or another /64
// in the same /48.
func TestOneSourcesFloodNeverHidesAnotherSourcesRecords(t *testing.T) {
	for name, tc := range map[string]struct{ flood, other, otherIP string }{
		"another IPv4 address":        {"192.0.2.7:1234", "198.51.100.9:1", "198.51.100.9"},
		"another /64 in the same /48": {"[2001:db8:1:2::1]:1234", "[2001:db8:1:3::1]:1234", "2001:db8:1:3::1"},
	} {
		t.Run(name, func(t *testing.T) {
			l, buf, _ := stoppedClockLog(nil)
			e := Event{Name: ConsentShown, Outcome: Success, ClientID: "client-1"}
			for range unauthBurst + 5 {
				l.RecordUnauthenticated(from(tc.flood), e)
			}
			l.RecordUnauthenticated(from(tc.other), e)
			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			if len(lines) != unauthBurst+1 {
				t.Fatalf("logged %d records, want %d: %s", len(lines), unauthBurst+1, buf.String())
			}
			last := lines[len(lines)-1]
			if !strings.Contains(last, `"remote_ip":"`+tc.otherIP+`"`) {
				t.Fatalf("the other source's record was dropped; last line: %s", last)
			}
			if strings.Contains(last, "suppressed") {
				t.Fatalf("the other source's record carries the first source's suppressed count: %s", last)
			}
		})
	}
}

func TestUnauthenticatedEventsAreRateLimitedPerSourceAndCountedAnyway(t *testing.T) {
	counted := 0
	l, buf, now := stoppedClockLog(func(string, string) { counted++ })
	r := from("192.0.2.7:1234")
	for range unauthBurst + 5 {
		l.RecordUnauthenticated(r, Event{Name: HostRejected, Outcome: Failure, Host: "evil.example"})
	}
	if n := strings.Count(buf.String(), "\n"); n != unauthBurst {
		t.Fatalf("logged %d records, want %d", n, unauthBurst)
	}
	if counted != unauthBurst+5 {
		t.Fatalf("observer saw %d events, want %d (suppressed ones count too)", counted, unauthBurst+5)
	}
	*now = now.Add(unauthWindow)
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

// An IPv6 sender rotating its interface ID within its own /64 shares one budget, as the OAuth
// rate limit groups it, so rotating addresses buys no fresh burst; each record still carries the
// address that sent it. Another /64 keeps its own budget:
// TestOneSourcesFloodNeverHidesAnotherSourcesRecords.
func TestAnIPv6SourceIsLimitedByItsSlash64AndLoggedByItsAddress(t *testing.T) {
	l, buf, _ := stoppedClockLog(nil)
	// The interface ID varies in its top bits, so only a key of /64 or shorter groups them.
	addr := func(i int) string { return fmt.Sprintf("2001:db8:1:2:%x::1", (i+1)<<12) }
	for i := range unauthBurst + 5 {
		l.RecordUnauthenticated(from("["+addr(i)+"]:1234"), Event{Name: HostRejected, Outcome: Failure, Host: "evil.example"})
	}
	if n := strings.Count(buf.String(), `"event":"host_rejected"`); n != unauthBurst {
		t.Fatalf("logged %d records from one /64, want %d (its burst):\n%s", n, unauthBurst, buf.String())
	}
	for i := range unauthBurst {
		if want := `"remote_ip":"` + addr(i) + `"`; !strings.Contains(buf.String(), want) {
			t.Errorf("no record carries the sender's own address %s", want)
		}
	}
	if t.Failed() {
		t.Log(buf.String())
	}
}

// stoppedClockLog is a JSON audit log on a stopped clock; a test advances the clock through now.
func stoppedClockLog(observe Observer) (l *Log, buf *bytes.Buffer, now *time.Time) {
	buf, now = new(bytes.Buffer), new(time.Time)
	*now = time.Unix(1_800_000_000, 0)
	return New(logging.New(buf, "json"), observe, func() time.Time { return *now }), buf, now
}

// from is a request whose remote address (host:port) is addr; its method and path do not matter to
// the limit.
func from(addr string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = addr
	return r
}

// An audit record carries its request's ID, once, through the proxy's logger (which adds it from the
// request's context); a record with no request carries none.
func TestARecordCarriesItsRequestsID(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	r = r.WithContext(logging.WithRequestID(r.Context(), "req-1"))
	for name, tc := range map[string]struct {
		record func(*Log)
		want   int
	}{
		"a request's record":                  {record: func(l *Log) { l.Record(r, Event{Name: TokenIssued, Outcome: Success}) }, want: 1},
		"an unauthenticated request's record": {record: func(l *Log) { l.RecordUnauthenticated(r, Event{Name: TokenRejected, Outcome: Failure}) }, want: 1},
		"no request":                          {record: func(l *Log) { l.Record(nil, Event{Name: KeyLoaded, Outcome: Success}) }},
	} {
		t.Run(name, func(t *testing.T) {
			l, buf, _ := stoppedClockLog(nil)
			tc.record(l)
			if strings.Count(buf.String(), "\n") != 1 {
				t.Fatalf("want one record: %q", buf.String())
			}
			line := buf.String()
			if strings.Count(line, `"request_id":"req-1"`) != tc.want || strings.Count(line, `"request_id"`) != tc.want {
				t.Fatalf("want the request ID %d time(s) in one line: %s", tc.want, buf.String())
			}
		})
	}
}
