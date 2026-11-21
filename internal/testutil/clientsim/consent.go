package clientsim

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ConsentTooSoon is the hint of the consent page the broker shows again to an Allow it got before
// the consent delay had passed.
const ConsentTooSoon = "Take a moment to check the details, then choose again."

// AnswerAllow sends Allow with post once the consent delay has passed, as a user does, and returns
// the answer, a 303 with a Location; any other answer is an error with its status and body. The
// wait is on the monotonic clock but the broker measures the delay on the wall clock, so a
// backward wall-clock step can make Allow too soon (#598): on that page only, it waits once more
// and sends Allow again. A broker that refuses Allow every time still fails.
func AnswerAllow(delay time.Duration, post func() (*http.Response, error)) (*http.Response, error) {
	for again := false; ; again = true {
		time.Sleep(delay + 100*time.Millisecond) // Allow is accepted only after the delay
		res, err := post()
		if err != nil {
			return nil, fmt.Errorf("consent answer: %w", err)
		}
		if res.StatusCode == http.StatusSeeOther && res.Header.Get("Location") != "" {
			return res, nil
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		switch tooSoon := res.StatusCode == http.StatusOK && strings.Contains(string(body), ConsentTooSoon); {
		case again:
			return nil, fmt.Errorf("consent answer after a too-soon page: %d, want a 303 to the IdP: %s", res.StatusCode, body)
		case !tooSoon:
			return nil, fmt.Errorf("consent answer: %d, want a 303 to the IdP: %s", res.StatusCode, body)
		}
	}
}
