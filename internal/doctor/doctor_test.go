package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExitCodeIsTheOROfFailedClasses(t *testing.T) {
	r := func(c Class, s Status) Result { return Result{Class: c, Status: s} }
	cases := []struct {
		name   string
		checks []Result
		want   int
	}{
		{"no checks", nil, 0},
		{"all pass", []Result{r(ClassProxy, Pass), r(ClassIdP, Pass)}, 0},
		{"warnings and skips do not fail", []Result{r(ClassProxy, Warn), r(ClassIdP, Skip)}, 0},
		{"proxy fails", []Result{r(ClassProxy, Fail), r(ClassIdP, Pass)}, ExitProxy},
		{"IdP fails", []Result{r(ClassProxy, Pass), r(ClassIdP, Fail)}, ExitIdP},
		{"both fail", []Result{r(ClassIdP, Fail), r(ClassProxy, Fail), r(ClassIdP, Fail)}, ExitProxy | ExitIdP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Report{Checks: tc.checks}).ExitCode(); got != tc.want {
				t.Fatalf("exit code %d, want %d", got, tc.want)
			}
		})
	}
	if ExitProxy|ExitIdP != 12 || ExitProxy == 2 || ExitIdP == 2 {
		t.Fatal("the documented exit codes are 4, 8 and 12, distinct from configuration errors (2)")
	}
}

func TestWriteJSONIsTheDocumentedShape(t *testing.T) {
	var b bytes.Buffer
	rep := Report{Checks: []Result{{Class: ClassIdP, Name: "n", Status: Warn, Message: "m", Fix: "f"}, {Class: ClassProxy, Name: "p", Status: Pass, Message: "ok"}}}
	if err := rep.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Checks []map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{{"class": "idp", "name": "n", "status": "warn", "message": "m", "fix": "f"}, {"class": "proxy", "name": "p", "status": "pass", "message": "ok"}}
	if len(got.Checks) != 2 || !equal(got.Checks[0], want[0]) || !equal(got.Checks[1], want[1]) {
		t.Fatalf("JSON %s", b.String())
	}
	b.Reset()
	if err := (Report{}).WriteJSON(&b); err != nil || !strings.Contains(b.String(), `"checks": []`) {
		t.Fatalf("an empty report is %q, want an empty checks array", b.String())
	}
}

func equal(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestWriteTextShowsStatusClassNameAndFix(t *testing.T) {
	var b bytes.Buffer
	Report{Checks: []Result{{Class: ClassIdP, Name: "entra tenant", Status: Fail, Message: "no tenant", Fix: "set it"}}}.WriteText(&b)
	if got := b.String(); !strings.Contains(got, "fail  idp    entra tenant: no tenant\n") || !strings.Contains(got, "fix: set it\n") {
		t.Fatalf("text %q", got)
	}
}

func TestSecretExpiryWarnsWithin30DaysAndFailsOnceExpired(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		expires time.Time
		status  Status
		inMsg   string
	}{
		{"not configured", time.Time{}, Skip, "not configured"},
		{"expired", now.Add(-time.Hour), Fail, "expired on 2026-11-06"},
		{"expires now", now, Fail, "expired"},
		{"30 days left warns", now.Add(30 * 24 * time.Hour), Warn, "in 30 days"},
		{"31 days left passes", now.Add(31 * 24 * time.Hour), Pass, "valid until 2026-12-07"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := SecretExpiry("EXPIRES_SETTING", tc.expires, now)
			if r.Class != ClassIdP || r.Status != tc.status || !strings.Contains(r.Message, tc.inMsg) {
				t.Fatalf("%+v, want %s with %q", r, tc.status, tc.inMsg)
			}
			if tc.status != Pass && !strings.Contains(r.Fix, "EXPIRES_SETTING") {
				t.Fatalf("fix %q does not name the setting", r.Fix)
			}
		})
	}
}

// A certificate's end date is its own, so there is no "not configured": it warns within 30 days,
// fails once passed, and the fix names the certificate file's setting.
func TestCertificateExpiryWarnsWithin30DaysAndFailsOnceExpired(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		notAfter time.Time
		status   Status
		inMsg    string
	}{
		{"expired", now.Add(-time.Hour), Fail, "client certificate expired on 2026-11-06"},
		{"expires now", now, Fail, "expired"},
		{"30 days left warns", now.Add(30 * 24 * time.Hour), Warn, "in 30 days"},
		{"31 days left passes", now.Add(31 * 24 * time.Hour), Pass, "valid until 2026-12-07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := CertificateExpiry("CERT_SETTING", tc.notAfter, now)
			if r.Class != ClassIdP || r.Name != "client certificate expiry" || r.Status != tc.status || !strings.Contains(r.Message, tc.inMsg) {
				t.Fatalf("%+v, want %s with %q", r, tc.status, tc.inMsg)
			}
			if tc.status != Pass && !strings.Contains(r.Fix, "CERT_SETTING") {
				t.Fatalf("fix %q does not name the setting", r.Fix)
			}
		})
	}
}
