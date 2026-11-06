package registration

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/corker/mcp-authproxy/internal/idp"
)

// ErrInvalidClient means client authentication failed; the broker answers `invalid_client`. The
// wrapped reason is for operator logs and never contains a credential.
var ErrInvalidClient = errors.New("registration: client authentication failed")

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Client assertion rules (ADR-0008 §6).
const (
	MaxAssertionLifetime = 5 * time.Minute
	AssertionLeeway      = idp.Leeway
	MaxJTILen            = 256
)

var assertionAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidClient, reason) }

// Authenticate checks the credentials of a /token or /revoke request: exactly the registered
// method, a matching client_id, secrets compared in constant time, and private_key_jwt per RFC 7523
// with aud = tokenEndpoint, exp at most 5 min ahead and a jti replay check.
func (c *staticClient) Authenticate(ctx context.Context, form url.Values, header http.Header, tokenEndpoint string, now time.Time) error {
	basicID, basicSecret, hasBasic := basicAuth(header)
	if hasBasic && basicID != c.id {
		return invalid("Basic client ID does not match")
	}
	if id := form.Get("client_id"); id != "" && id != c.id {
		return invalid("client_id does not match")
	}
	used := presented(hasBasic, form)
	if len(used) > 1 {
		return invalid("more than one authentication method")
	}
	got := None
	if len(used) == 1 {
		got = used[0]
	}
	if got != c.method {
		return invalid(fmt.Sprintf("registered %s, sent %s", c.method, got))
	}
	switch c.method {
	case ClientSecretBasic:
		return c.checkSecret(basicSecret)
	case ClientSecretPost:
		return c.checkSecret(form.Get("client_secret"))
	case PrivateKeyJWT:
		if form.Get("client_assertion_type") != clientAssertionType {
			return invalid("client_assertion_type")
		}
		return c.checkAssertion(ctx, form.Get("client_assertion"), tokenEndpoint, now)
	}
	return nil
}

func presented(hasBasic bool, form url.Values) []AuthMethod {
	var m []AuthMethod
	if hasBasic {
		m = append(m, ClientSecretBasic)
	}
	if form.Has("client_secret") {
		m = append(m, ClientSecretPost)
	}
	if form.Has("client_assertion") || form.Has("client_assertion_type") {
		m = append(m, PrivateKeyJWT)
	}
	return m
}

// basicAuth parses RFC 6749 §2.3.1 Basic credentials, which are form-encoded inside.
func basicAuth(h http.Header) (id, secret string, ok bool) {
	r := http.Request{Header: h}
	id, secret, ok = r.BasicAuth()
	if !ok {
		return "", "", false
	}
	var err1, err2 error
	id, err1 = url.QueryUnescape(id)
	secret, err2 = url.QueryUnescape(secret)
	if err1 != nil || err2 != nil {
		return "", "", true
	}
	return id, secret, true
}

func (c *staticClient) checkSecret(got string) error {
	want, sent := sha256.Sum256([]byte(c.secret)), sha256.Sum256([]byte(got))
	if subtle.ConstantTimeCompare(want[:], sent[:]) != 1 {
		return invalid("client secret does not match")
	}
	return nil
}

func (c *staticClient) checkAssertion(ctx context.Context, raw, tokenEndpoint string, now time.Time) error {
	claims, err := idp.VerifySignature(ctx, raw, c.keys, assertionAlgs)
	if err != nil {
		return invalid("client assertion: " + err.Error())
	}
	str := func(k string) string { s, _ := claims[k].(string); return s }
	if str("iss") != c.id || str("sub") != c.id {
		return invalid("client assertion iss and sub must be the client ID")
	}
	if !audienceContains(claims["aud"], tokenEndpoint) {
		return invalid("client assertion aud is not our token endpoint")
	}
	exp, ok := numericDate(claims["exp"])
	switch {
	case !ok:
		return invalid("client assertion has no exp")
	case !now.Before(exp.Add(AssertionLeeway)):
		return invalid("client assertion expired")
	case exp.After(now.Add(MaxAssertionLifetime + AssertionLeeway)):
		return invalid("client assertion exp is more than 5 minutes ahead")
	}
	for _, k := range []string{"nbf", "iat"} {
		if t, ok := numericDate(claims[k]); ok && t.After(now.Add(AssertionLeeway)) {
			return invalid("client assertion " + k + " is in the future")
		}
	}
	jti := str("jti")
	if jti == "" || len(jti) > MaxJTILen {
		return invalid("client assertion jti missing or too long")
	}
	seen, err := c.jti.Seen(ctx, c.id+"\x00"+jti, exp.Add(AssertionLeeway))
	if err != nil {
		return fmt.Errorf("registration: jti cache: %w", err)
	}
	if seen {
		return invalid("client assertion replayed")
	}
	return nil
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}
