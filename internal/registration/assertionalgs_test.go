package registration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// The broker advertises AssertionAlgs as token_endpoint_auth_signing_alg_values_supported: a client
// assertion signed with each of them is accepted, and one signed with another asymmetric algorithm
// is refused, so the metadata never advertises what /token refuses, or hides what it accepts.
func TestAClientAssertionIsAcceptedExactlyForTheAdvertisedAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type signer struct {
		kid string
		key crypto.Signer
	}
	signers := map[string]signer{"RS256": {"rsa", rsaKey}, "PS256": {"rsa", rsaKey}, "RS384": {"rsa", rsaKey}, "PS512": {"rsa", rsaKey},
		"ES256": {"p256", ecKey}, "ES384": {"p384", ec384}}
	keys := idp.StaticKeys{Keys: []jose.JSONWebKey{{Key: rsaKey.Public(), KeyID: "rsa"}, {Key: ecKey.Public(), KeyID: "p256"}, {Key: ec384.Public(), KeyID: "p384"}}}
	advertised := AssertionAlgs()
	for alg, s := range signers {
		t.Run(alg, func(t *testing.T) {
			c := &clientAuth{id: "jwt", methods: []AuthMethod{PrivateKeyJWT}, keys: keys, jti: NewStoreJTICache(memory.New())}
			sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: s.key}, (&jose.SignerOptions{}).WithHeader("kid", s.kid))
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]any{"iss": "jwt", "sub": "jwt", "aud": tokenEndpoint, "jti": fakeidp.NewGUID(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
			jws, err := sig.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := jws.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{"client_id": {"jwt"}, "client_assertion_type": {clientAssertionType}, "client_assertion": {raw}}
			err = c.Authenticate(context.Background(), form, http.Header{}, tokenEndpoint, now)
			if want := slices.Contains(advertised, alg); (err == nil) != want {
				t.Fatalf("%s (advertised %v): err = %v", alg, want, err)
			}
		})
	}
	if !slices.Contains(advertised, "ES256") || !slices.Contains(advertised, "RS256") || !slices.Contains(advertised, "PS256") {
		t.Fatalf("AssertionAlgs() = %v, want RS256, PS256 and ES256 among them", advertised)
	}
}
