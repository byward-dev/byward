package token

import (
	"reflect"
	"testing"
)

// goldenKey seals goldenAccess; a fixed key, so the token below opens in every run.
const goldenKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"

// goldenAccess is a format-2 access token with every asserted claim, sealed with goldenKey for
// resourceA by the code before the claims had one owner (L76). Clients hold such tokens across an
// upgrade, so it must keep opening.
const goldenAccess = "byw_at_AgZnb2xkZW4D7zbO1LtAOJ3u0jVepVxhED-5KGVgWZHbaAOWby679Nn-5OVSYCm4Gyf9fBUPS7dA2IXpy9kYYKGQizu8iGyj3BgVnUMUpHmL3ZmE7W4sl4l8uSP3Vn7fILRaxqENR5YUJMn-V9iClM-hx6J-8tFRvZVRgtZSs-F0B2Ne0sZdx7KMZ8_r8BAc3GMYUccL86CwzaPYVXiCqfNn7oRzJoYtazuCvYDsqOLYh2mR79vhTz5rRvN25dMYjzacdtMdTw4cPZDydun_clgwgZ6WTIkjVEXuEgNSm1WyCT7jkOMbOw"

// goldenWire is the sealed JSON of goldenClaims: the wire names a token's claims keep.
const goldenWire = `{"gid":"g-1","sub":"tid-1:oid-1","iat":1793966400,"exp":1793970000,"cid":"client-1",` +
	`"rol":["byward.user","byward.admin"],"grp":["g1","g2"],"eml":"alex@contoso.example","emv":true,"nam":"Alex Doe"}`

func goldenClaims() Claims {
	c := claims()
	c.Roles, c.Groups, c.Email, c.EmailVerified, c.Name = []string{"byward.user", "byward.admin"}, []string{"g1", "g2"}, "alex@contoso.example", true, "Alex Doe"
	return c
}

func goldenSealer(t *testing.T) *Sealer {
	t.Helper()
	return sealerFor(t, mustRing(t, keyDir(t, map[string]string{"golden": goldenKey})), resourceA)
}

// An access token sealed by an earlier build, with every asserted claim, opens with the same claims.
func TestAnAccessTokenSealedByAnEarlierBuildOpensWithItsClaims(t *testing.T) {
	got, err := goldenSealer(t).Open(Access, goldenAccess)
	if err != nil {
		t.Fatalf("the golden token does not open: %v", err)
	}
	want := goldenClaims()
	if !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("times %v, %v; want %v, %v", got.IssuedAt, got.ExpiresAt, want.IssuedAt, want.ExpiresAt)
	}
	got.IssuedAt, got.ExpiresAt = want.IssuedAt, want.ExpiresAt
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claims %+v; want %+v", got, want)
	}
}

// A new access token seals its claims under the same wire names, and leaves out the claims it does
// not carry, so an earlier build (another replica during a rolling upgrade, or a rollback) still
// opens it, and a token without claims stays small.
func TestAccessTokensSealTheirClaimsUnderTheSameWireNames(t *testing.T) {
	s := goldenSealer(t)
	for _, c := range []struct {
		name   string
		claims Claims
		wire   string
	}{
		{"every claim", goldenClaims(), goldenWire},
		{"no claims", claims(), `{"gid":"g-1","sub":"tid-1:oid-1","iat":1793966400,"exp":1793970000,"cid":"client-1"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			plain, err := s.openPlain(Access, mustSeal(t, s, Access, c.claims))
			if err != nil {
				t.Fatal(err)
			}
			if string(plain) != c.wire {
				t.Fatalf("sealed JSON\n%s\nwant\n%s", plain, c.wire)
			}
		})
	}
}
