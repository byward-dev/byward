package entra

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

var graphUserRead = []string{"https://graph.microsoft.com/User.Read"}

// signedInAssertion signs a user in and returns their tenant and access_as_user token, the
// On-Behalf-Of assertion (ADR-0012 §3).
func signedInAssertion(t *testing.T, e *env) (tid, assertion string) {
	t.Helper()
	id, tokens, err := callback(t, e)
	if err != nil {
		t.Fatal(err)
	}
	tid, _, _ = strings.Cut(id.Subject, ":")
	return tid, tokens.AccessToken
}

// ADR-0017 §2: the stored access_as_user token is exchanged at the user's tenant for a token for
// the downstream scopes.
func TestOnBehalfOfReturnsADownstreamToken(t *testing.T) {
	e := newEnv(t, Config{})
	tid, assertion := signedInAssertion(t, e)
	tok, err := e.p.OnBehalfOf(context.Background(), tid, assertion, graphUserRead)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || tok.AccessToken == assertion || !tok.ExpiresAt.After(now()) {
		t.Fatalf("downstream token %+v: want a new token expiring after now", tok.ExpiresAt)
	}
}

// ADR-0017 §5: the errors that get answers of their own keep their AADSTS code or OAuth error,
// carry an operator hint, and never carry the claims challenge.
func TestOnBehalfOfErrorsKeepTheirCodeAndHint(t *testing.T) {
	cases := []struct {
		name    string
		failure *fakeidp.Failure
		code    int
		oauth   string
		hint    string
	}{
		{"consent missing", &fakeidp.ConsentRequired, CodeConsentRequired, "invalid_grant", "admin consent"},
		{"Conditional Access", &fakeidp.InteractionRequired, 50079, OAuthInteractionNeeded, "Conditional Access"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, Config{})
			tid, assertion := signedInAssertion(t, e)
			e.fake.Set(fakeidp.FailToken(fakeidp.GrantJWTBearer, c.failure))
			_, err := e.p.OnBehalfOf(context.Background(), tid, assertion, graphUserRead)
			var ie *idp.Error
			if !errors.As(err, &ie) {
				t.Fatalf("err = %v, want *idp.Error", err)
			}
			if ie.Code != c.code || ie.OAuth != c.oauth || !strings.Contains(ie.OperatorHint, c.hint) {
				t.Fatalf("code %d oauth %q hint %q, want %d %q with %q", ie.Code, ie.OAuth, ie.OperatorHint, c.code, c.oauth, c.hint)
			}
			if c.failure.Claims != "" && strings.Contains(err.Error()+ie.Description+ie.OperatorHint, "polids") {
				t.Fatal("the claims challenge reached the error")
			}
		})
	}
}

// A token that is not our own access_as_user token is refused by Entra (AADSTS50013), and a bad
// tenant is refused before any request.
func TestOnBehalfOfRefusesWrongInput(t *testing.T) {
	e := newEnv(t, Config{})
	tid, _ := signedInAssertion(t, e)
	foreign := e.fake.Mint(map[string]any{"aud": "https://graph.microsoft.com", "tid": tid, "oid": fakeidp.NewGUID(), "iss": issuerFor(tid), "ver": "2.0"})
	_, err := e.p.OnBehalfOf(context.Background(), tid, foreign, graphUserRead)
	if ie := (*idp.Error)(nil); !errors.As(err, &ie) || ie.Code != 50013 {
		t.Fatalf("a foreign assertion: %v, want AADSTS50013", err)
	}
	for name, args := range map[string]struct {
		tid, assertion string
		scopes         []string
	}{
		"tenant not a GUID": {"contoso.example", "x", graphUserRead},
		"no assertion":      {tid, "", graphUserRead},
		"no scopes":         {tid, "x", nil},
	} {
		if _, err := e.p.OnBehalfOf(context.Background(), args.tid, args.assertion, args.scopes); idp.ClassOf(err) != idp.Fatal {
			t.Errorf("%s: %v, want a fatal error", name, err)
		}
	}
}

// oboAnswer answers the On-Behalf-Of grant with body and passes every other request to next.
type oboAnswer struct {
	next http.RoundTripper
	body string
}

func (a oboAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		if f, _ := url.ParseQuery(string(b)); f.Get("grant_type") == grantJWTBearer {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(a.body)), Request: r}, nil
		}
	}
	return a.next.RoundTrip(r)
}

// A success answer without a usable bearer token is an error, never a token to cache and send.
func TestOnBehalfOfRefusesAnAnswerWithoutABearerToken(t *testing.T) {
	for name, body := range map[string]string{
		"no access token":   `{"token_type":"Bearer","expires_in":3600}`,
		"no lifetime":       `{"access_token":"t","token_type":"Bearer","expires_in":0}`,
		"not a bearer type": `{"access_token":"t","token_type":"pop","expires_in":3600}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{})
			tid, assertion := signedInAssertion(t, e)
			c := *e.p.fetch.Client
			c.Transport = oboAnswer{next: c.Transport, body: body}
			e.p.fetch.Client = &c
			if tok, err := e.p.OnBehalfOf(context.Background(), tid, assertion, graphUserRead); err == nil || tok.AccessToken != "" {
				t.Fatalf("token set %v, err %v; want an error and no token", tok.AccessToken != "", err)
			}
		})
	}
}

// The admin-consent URL of the Microsoft identity platform (v2), for the user's tenant.
func TestAdminConsentURLForTheUsersTenant(t *testing.T) {
	e := newEnv(t, Config{})
	tid := fakeidp.NewGUID()
	u, err := url.Parse(e.p.AdminConsentURL(tid, []string{"https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/Mail.Read"}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.Scheme+"://"+u.Host+u.Path, Authority+"/"+tid+"/v2.0/adminconsent"; got != want {
		t.Errorf("endpoint %s, want %s", got, want)
	}
	q := u.Query()
	for k, want := range map[string]string{"client_id": e.client.ID, "redirect_uri": redirect,
		"scope": "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read"} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}
