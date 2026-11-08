package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// On-Behalf-Of presents the grant's stored IdP access token until it expires (ADR-0017 §2); a grant
// without one, or no grant, yields no token rather than an empty one.
func TestIdPAccessTokenIsTheGrantsStoredToken(t *testing.T) {
	const idpLife = 20 * time.Minute
	t.Run("stored", func(t *testing.T) {
		e := newEnv(t)
		e.fake.Set(fakeidp.WithTokenLifetime(idpLife))
		e.offline(t)
		tok, exp, err := e.b.IdPAccessToken(context.Background(), lastGrant(e.st))
		if err != nil || tok == "" || !exp.Equal(e.now.Add(idpLife)) {
			t.Fatalf("token set %v, expiry %v, err %v; want a token expiring at %v", tok != "", exp, err, e.now.Add(idpLife))
		}
	})
	t.Run("the grant ends first", func(t *testing.T) {
		e := newEnv(t)
		e.fake.Set(fakeidp.WithTokenLifetime(idpLife))
		e.offline(t)
		ends := e.now.Add(5 * time.Minute) // before the IdP token's expiry
		if err := e.st.UpdateGrant(context.Background(), lastGrant(e.st), ends); err != nil {
			t.Fatal(err)
		}
		if _, exp, err := e.b.IdPAccessToken(context.Background(), lastGrant(e.st)); err != nil || !exp.Equal(ends) {
			t.Fatalf("expiry %v, err %v; want the grant's own end %v", exp, err, ends)
		}
	})
	t.Run("a stored token without an expiry ends with its grant", func(t *testing.T) {
		e := newEnv(t)
		e.resealBlob(t, func(plain []byte) []byte {
			s, err := unmarshalSecrets(plain)
			if err != nil {
				t.Fatal(err)
			}
			s.Tokens.Expiry = time.Time{} // the IdP gave none
			return marshalSecrets(s.Tokens, s.Claims)
		})
		e.offline(t)
		ends := e.now.Add(5 * time.Minute)
		if err := e.st.UpdateGrant(context.Background(), lastGrant(e.st), ends); err != nil {
			t.Fatal(err)
		}
		if _, exp, err := e.b.IdPAccessToken(context.Background(), lastGrant(e.st)); err != nil || !exp.Equal(ends) {
			t.Fatalf("expiry %v, err %v; want the grant's end %v", exp, err, ends)
		}
	})
	t.Run("none stored", func(t *testing.T) {
		e := newEnv(t)
		e.resealBlob(t, func(plain []byte) []byte {
			s, err := unmarshalSecrets(plain)
			if err != nil {
				t.Fatal(err)
			}
			s.Tokens.AccessToken = ""
			return marshalSecrets(s.Tokens, s.Claims)
		})
		e.offline(t)
		if tok, _, err := e.b.IdPAccessToken(context.Background(), lastGrant(e.st)); !errors.Is(err, ErrNoIdPAccessToken) || tok != "" {
			t.Fatalf("err %v, want ErrNoIdPAccessToken and no token", err)
		}
	})
	t.Run("no grant", func(t *testing.T) {
		e := newEnv(t)
		if _, _, err := e.b.IdPAccessToken(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("err %v, want store.ErrNotFound", err)
		}
	})
}
