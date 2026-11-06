package registration

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/ssrfguard"
)

// ErrInvalidClient means client authentication failed; the broker answers `invalid_client`. The
// wrapped reason is for operator logs and never contains a credential.
var ErrInvalidClient = errors.New("registration: client authentication failed")

// ErrKeysRefused wraps ErrInvalidClient when the keys at a client's jwks_uri are definitely unusable
// (refused address, another status, an invalid or oversize body, keys breaking the registered-key
// rules), as opposed to a wrong assertion, so the operator log can say why.
var ErrKeysRefused = fmt.Errorf("%w: client keys refused", ErrInvalidClient)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Client assertion rules (ADR-0008 §6).
const (
	MaxAssertionLifetime = 5 * time.Minute
	AssertionLeeway      = idp.Leeway
	MaxJTILen            = 256
)

var assertionAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidClient, reason) }

// clientAuth is how a registered client authenticates at /token: the methods it registered (one for
// static clients; a CIMD document may list several, draft-ietf-oauth-client-id-metadata-document-03
// §5) and its credential. Static, CIMD and DCR clients embed it; secret stays empty for the latter
// two (ADR-0008 §5).
type clientAuth struct {
	id      string
	methods []AuthMethod
	secret  string
	keys    idp.KeySource
	jti     JTICache
}

func (c clientAuth) String() string {
	return fmt.Sprintf("registration.clientAuth{id:%s methods:%v}", c.id, c.methods)
}
func (c clientAuth) GoString() string { return c.String() }

// Format makes every fmt verb use String, so no verb can reach the secret by reflection.
func (c clientAuth) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// Authenticate checks the credentials of a /token or /revoke request: one of the registered
// methods, a matching client_id, secrets compared in constant time, and private_key_jwt per RFC 7523
// with aud = tokenEndpoint, exp at most 5 min ahead and a jti replay check.
func (c *clientAuth) Authenticate(ctx context.Context, form url.Values, header http.Header, tokenEndpoint string, now time.Time) error {
	basicID, basicSecret, hasBasic, err := basicAuth(header)
	if err != nil {
		return invalid("Basic credentials are not form-encoded")
	}
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
	if !slices.Contains(c.methods, got) {
		names := make([]string, len(c.methods))
		for i, m := range c.methods {
			names[i] = string(m)
		}
		return invalid(fmt.Sprintf("registered %s, sent %s", strings.Join(names, " or "), got))
	}
	switch got {
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
func basicAuth(h http.Header) (id, secret string, ok bool, err error) {
	r := http.Request{Header: h}
	id, secret, ok = r.BasicAuth()
	if !ok {
		return "", "", false, nil
	}
	if id, err = url.QueryUnescape(id); err != nil {
		return "", "", true, err
	}
	if secret, err = url.QueryUnescape(secret); err != nil {
		return "", "", true, err
	}
	return id, secret, true, nil
}

func (c *clientAuth) checkSecret(got string) error {
	want, sent := sha256.Sum256([]byte(c.secret)), sha256.Sum256([]byte(got))
	if subtle.ConstantTimeCompare(want[:], sent[:]) != 1 {
		return invalid("client secret does not match")
	}
	return nil
}

func (c *clientAuth) checkAssertion(ctx context.Context, raw, tokenEndpoint string, now time.Time) error {
	claims, err := idp.VerifySignature(ctx, raw, c.keys, assertionAlgs)
	if errors.Is(err, idp.ErrKeysUnavailable) {
		if keysTransient(err) { // a jwks_uri that cannot be fetched for now is not a failed authentication (§6.1)
			return fmt.Errorf("%w: client assertion keys: %v", ErrUnavailable, err)
		}
		return fmt.Errorf("%w: %v", ErrKeysRefused, err)
	}
	if errors.Is(err, ErrKeysRefused) { // jwks_uri keys breaking the registered-key rules (clientKeys)
		return err
	}
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

// parseClientJWKS parses a client's registered JWK Set: public keys only, RSA at least MinRSABits,
// at least one usable signing key.
func parseClientJWKS(raw []byte) (idp.StaticKeys, error) {
	set, err := idp.ParseJWKS(raw)
	if err != nil {
		return idp.StaticKeys{}, fmt.Errorf("jwks: %w", err)
	}
	for _, k := range set.Keys {
		if err := checkClientKey(k); err != nil {
			return idp.StaticKeys{}, err
		}
	}
	if idp.SigningKeys(set) == 0 {
		return idp.StaticKeys{}, errors.New("jwks: no usable public signing key")
	}
	return idp.StaticKeys(set), nil
}

// checkClientKey applies the rules for a client's registered keys, inline or from a jwks_uri:
// public keys only, RSA at least MinRSABits.
func checkClientKey(k jose.JSONWebKey) error {
	if !k.IsPublic() {
		return errors.New("jwks: contains a private key; register public keys only")
	}
	if rk, ok := k.Key.(*rsa.PublicKey); ok && rk.N.BitLen() < MinRSABits {
		return fmt.Errorf("jwks: RSA keys must be at least %d bits", MinRSABits)
	}
	return nil
}

// keysTransient reports whether a failed jwks_uri fetch is worth retrying later, the same split as
// for metadata documents (ssrfguard.Transient): a 5xx, 408 or 429, network trouble or a timeout.
// A refused address, another status, an oversize or invalid body, or unusable keys are definite.
func keysTransient(err error) bool {
	var se *idp.StatusError
	switch {
	case errors.As(err, &se):
		return se.Code >= 500 || se.Code == http.StatusRequestTimeout || se.Code == http.StatusTooManyRequests
	case ssrfguard.RefusedAddress(err):
		return false
	}
	var ue *url.Error
	var ne net.Error // a connection reset while the body was read is not wrapped in *url.Error
	return errors.As(err, &ue) || errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
