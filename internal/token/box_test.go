package token

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

func boxRing(t *testing.T, ids ...string) *KeyRing {
	t.Helper()
	files := map[string]string{}
	for _, id := range ids {
		files[id] = randomKey(t)
	}
	return mustRing(t, keyDir(t, files))
}

func TestBoxRoundTripAndBindings(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	ring := boxRing(t, "k1")
	login, _ := NewBox(ring, "login", clock)
	idpTokens, _ := NewBox(ring, "idp-tokens", clock)

	s, err := login.Seal([]byte("flow"), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := login.Open(s); err != nil || !bytes.Equal(got, []byte("flow")) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := idpTokens.Open(s); err == nil {
		t.Fatal("a box opened for another purpose")
	}
	if _, err := NewBox(boxRing(t, "k1"), "login", clock); err != nil {
		t.Fatal(err)
	}
	other, _ := NewBox(boxRing(t, "k1"), "login", clock)
	if _, err := other.Open(s); err == nil {
		t.Fatal("a box opened with a different key of the same ID")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(s)
	for i := range raw {
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 1
		if _, err := login.Open(base64.RawURLEncoding.EncodeToString(tampered)); err == nil {
			t.Fatalf("tampered byte %d opened", i)
		}
	}
}

func TestBoxExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, _ := NewBox(boxRing(t, "k1"), "login", func() time.Time { return now })
	if _, err := b.Seal([]byte("x"), now); err == nil {
		t.Fatal("sealed an already expired box")
	}
	s, _ := b.Seal([]byte("x"), now.Add(time.Minute))
	now = now.Add(time.Minute)
	if _, err := b.Open(s); err == nil {
		t.Fatal("opened an expired box")
	}
}

func FuzzBoxOpen(f *testing.F) {
	fuzzRing = mustRing(f, keyDir(f, map[string]string{"k1": randomKey(f)}))
	f.Add("")
	f.Add("AQJrMQ")
	f.Fuzz(func(t *testing.T, s string) {
		b, _ := NewBox(boxRingF(), "login", nil)
		_, _ = b.Open(s) // must not panic
	})
}

var fuzzRing *KeyRing

func boxRingF() *KeyRing { return fuzzRing }
