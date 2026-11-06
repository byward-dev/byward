package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Outbound budgets (docs/quality-lenses.md, "Default budgets").
const (
	DefaultTimeout = 5 * time.Second
	MaxBodyBytes   = 64 << 10
	DefaultRetries = 2
)

// NewHTTPClient is the outbound client for IdP calls: a 5 s timeout and no redirects, so a
// configured endpoint can never be bounced elsewhere.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       DefaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Fetcher makes bounded IdP requests. GETs (discovery, JWKS) retry with jitter; POSTs to the
// token endpoint never retry, since codes are single-use.
type Fetcher struct {
	Client  *http.Client
	Retries int
	// Backoff is the base delay between GET retries; 0 retries immediately.
	Backoff time.Duration
}

// NewFetcher returns a Fetcher with the default budgets; nil client means NewHTTPClient.
func NewFetcher(c *http.Client) *Fetcher {
	if c == nil {
		c = NewHTTPClient()
	}
	return &Fetcher{Client: c, Retries: DefaultRetries, Backoff: 200 * time.Millisecond}
}

// GetJSON fetches a JSON document of at most MaxBodyBytes into dst.
func (f *Fetcher) GetJSON(ctx context.Context, endpoint string, dst any) error {
	var last error
	for attempt := 0; attempt <= f.Retries; attempt++ {
		if attempt > 0 && f.Backoff > 0 {
			d := f.Backoff*time.Duration(attempt) + rand.N(f.Backoff) //nolint:gosec // jitter, not security
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
			}
		}
		retry, err := f.getOnce(ctx, endpoint, dst)
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			break
		}
	}
	return last
}

func (f *Fetcher) getOnce(ctx context.Context, endpoint string, dst any) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return ctx.Err() == nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readLimited(resp.Body)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests,
			fmt.Errorf("GET %s: status %d", redactURL(endpoint), resp.StatusCode)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return false, fmt.Errorf("GET %s: %w", redactURL(endpoint), err)
	}
	return false, nil
}

// TokenResponse is a token endpoint reply, success or error.
type TokenResponse struct {
	Status int
	Header http.Header

	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	TraceID          string `json:"trace_id"`
	CorrelationID    string `json:"correlation_id"`
}

// Tokens converts a successful response, with Expiry from now.
func (r *TokenResponse) Tokens(now time.Time) Tokens {
	t := Tokens{IDToken: r.IDToken, AccessToken: r.AccessToken, RefreshToken: r.RefreshToken}
	if r.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(r.ExpiresIn) * time.Second)
	}
	return t
}

// PostToken sends a token request. A non-2xx response is returned with its error fields and a nil
// error; err is only for transport failures and malformed replies.
func (f *Fetcher) PostToken(ctx context.Context, endpoint string, form url.Values, header http.Header) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	tr := &TokenResponse{}
	if err := json.Unmarshal(body, tr); err != nil {
		return nil, fmt.Errorf("token endpoint returned status %d with a non-JSON body", resp.StatusCode)
	}
	tr.Status, tr.Header = resp.StatusCode, resp.Header
	if resp.StatusCode/100 == 2 && tr.Error == "" && tr.AccessToken == "" && tr.IDToken == "" {
		return nil, errors.New("token endpoint returned no tokens")
	}
	return tr, nil
}

// OK reports a successful token response.
func (r *TokenResponse) OK() bool { return r.Status/100 == 2 && r.Error == "" }

func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("response body larger than %d bytes", MaxBodyBytes)
	}
	return bytes.TrimSpace(body), nil
}

// redactURL drops the query, which may carry codes or state.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "<invalid URL>"
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}
