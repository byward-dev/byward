package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
)

// A private_key_jwt assertion is single use across servers that share the store (ADR-0008 §6,
// #227): the replay cache lives in the store, not in each process, so a second replica refuses an
// assertion the first one accepted.
func TestAClientAssertionAcceptedByOneServerIsAReplayOnAnotherSharingTheStore(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	env := gateEnv(t)
	clientsFile := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "BYWARD_STATIC_CLIENTS_FILE="); ok {
			clientsFile = v
		}
	}
	if err := os.WriteFile(clientsFile, []byte(`{"clients":[{"client_id":"jwt-app","token_endpoint_auth_method":"private_key_jwt",`+
		`"redirect_uris":["https://app.example/cb"],"jwks":`+string(jwks)+`}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	// clientOn wires a server on cfg, as a replica would start, and returns its view of the client.
	clientOn := func() registration.Client {
		t.Helper()
		var got broker.Config
		orig := newBroker
		newBroker = func(c broker.Config) (*broker.Broker, error) { got = c; return orig(c) }
		defer func() { newBroker = orig }()
		s, err := New(cfg, logging.New(io.Discard, "json"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if s.closeStore != nil {
				_ = s.closeStore()
			}
		})
		c, err := got.Clients.Client(context.Background(), "jwt-app")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b := clientOn(), clientOn()

	const tokenEndpoint = "https://m.example/token"
	now := time.Now()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]any{"iss": "jwt-app", "sub": "jwt-app", "aud": tokenEndpoint,
		"exp": now.Add(2 * time.Minute).Unix(), "iat": now.Unix(), "jti": "0b9f6f7e-2a49-4c4f-9a0e-6d3f1c2b8a51"})
	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	assertion, _ := jws.CompactSerialize()
	form := map[string][]string{"client_id": {"jwt-app"}, "client_assertion": {assertion},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}}

	if err := a.Authenticate(context.Background(), form, http.Header{}, tokenEndpoint, now); err != nil {
		t.Fatalf("first use on server A: %v", err)
	}
	if err := b.Authenticate(context.Background(), form, http.Header{}, tokenEndpoint, now); !errors.Is(err, registration.ErrInvalidClient) || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay on server B: %v, want the replay refused", err)
	}
}
