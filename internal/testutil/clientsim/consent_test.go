package clientsim

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// AnswerAllow waits out the delay before each Allow it sends, and sends it again only when the broker
// showed the page again as too soon, and only once: a 303 is returned as it is, and any other answer
// is an error naming its status and body, and whether it came after a too-soon page (#598).
func TestAnswerAllowRetriesATooSoonAnswerOnce(t *testing.T) {
	type answer func() (*http.Response, error)
	toIdP := func() (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": {"https://idp.example/authorize"}}, Body: http.NoBody}, nil
	}
	page := func(status int, body string) answer {
		return func() (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
	}
	tooSoon := page(http.StatusOK, "<p>"+ConsentTooSoon+"</p>")
	refused := errors.New("connection refused")
	for _, tc := range []struct {
		name    string
		answers []answer
		want    string // the error's text; "" for the 303
		cause   error  // the error AnswerAllow's error must wrap, if any
	}{
		{"allowed at once", []answer{toIdP}, "", nil},
		{"too soon, then allowed", []answer{tooSoon, toIdP}, "", nil},
		{"too soon twice", []answer{tooSoon, tooSoon}, "consent answer after a too-soon page: 200, want a 303 to the IdP: <p>" + ConsentTooSoon, nil},
		{"refused", []answer{page(http.StatusForbidden, "opened in another browser")}, "consent answer: 403, want a 303 to the IdP: opened in another browser", nil},
		{"too soon, then refused", []answer{tooSoon, page(http.StatusForbidden, "opened in another browser")}, "consent answer after a too-soon page: 403, want a 303 to the IdP: opened in another browser", nil},
		{"a 303 without a Location", []answer{page(http.StatusSeeOther, "")}, "consent answer: 303, want a 303 to the IdP: ", nil},
		{"a 200 that is not the too-soon page", []answer{page(http.StatusOK, "something else")}, "consent answer: 200, want a 303 to the IdP: something else", nil},
		{"the request failed", []answer{func() (*http.Response, error) { return nil, refused }}, "consent answer: connection refused", refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const delay = 150 * time.Millisecond // above AnswerAllow's 100ms margin, so the check sees the delay itself
			last, sent := time.Now(), 0
			res, err := AnswerAllow(delay, func() (*http.Response, error) {
				sent++
				if waited := time.Since(last); waited < delay {
					t.Errorf("Allow %d sent %v after the previous answer or the start, before the delay of %v", sent, waited, delay)
				}
				defer func() { last = time.Now() }()
				if sent > len(tc.answers) {
					t.Fatalf("Allow sent %d times, want %d", sent, len(tc.answers))
				}
				return tc.answers[sent-1]()
			})
			if sent != len(tc.answers) {
				t.Fatalf("Allow sent %d times, want %d", sent, len(tc.answers))
			}
			switch {
			case tc.want == "" && (err != nil || res.StatusCode != http.StatusSeeOther):
				t.Fatalf("answer %v, %v; want the 303", res, err)
			case tc.want != "" && (err == nil || res != nil || !strings.HasPrefix(err.Error(), tc.want)):
				t.Fatalf("answer %v, error %v; want no answer and %q", res, err, tc.want)
			case tc.cause != nil && !errors.Is(err, tc.cause):
				t.Fatalf("error %v does not wrap the request's", err)
			}
		})
	}
}
