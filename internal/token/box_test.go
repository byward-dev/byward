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

// Boxes outlive releases: every grant's IdP tokens, remembered consents, sign-ins in flight and MCP
// session IDs are stored in them. A box sealed by an earlier build (v0.2.0 or later) still opens,
// and a box this build seals carries the layout byte 0x02, so an earlier build (after a rollback)
// opens it too. It is the box's own version, which a new proxy-token formatVersion (DPoP's cnf
// claim, say) must not move (L161). The box below was sealed with this test key, which protects
// nothing.
func TestABoxSealedByAnEarlierBuildOpensAndANewBoxKeepsItsLayoutByte(t *testing.T) {
	const (
		key    = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
		sealed = "AgJrMQAAAAD0hlcAw5RYjIcB06RDHCZDmZ7JsAA-_EuTUYbe2q0JYdO7y87kNVO6tuF4PdX1IzoIlw2wn4RI"
	)
	ring := mustRing(t, keyDir(t, map[string]string{"k1": key}))
	box, err := NewBox(ring, "login", func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if got, err := box.Open(sealed); err != nil || string(got) != "sealed by box version 2" {
		t.Fatalf("Open = %q, %v; want the box an earlier build sealed", got, err)
	}
	fresh, err := box.Seal([]byte("x"), time.Unix(1_800_000_600, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(fresh)
	if len(raw) == 0 {
		t.Fatal("a new box decodes to nothing")
	}
	if raw[0] != 0x02 {
		t.Fatalf("a new box's layout byte is %#x; v0.2.0 and later open only 0x02", raw[0])
	}
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

func TestBoxJSONRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, _ := NewBox(boxRing(t, "k1"), "login", func() time.Time { return now })
	type doc struct {
		A string `json:"a"`
	}
	s, err := b.SealJSON(doc{A: "x"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var got doc
	if err := b.OpenJSON(s, &got); err != nil || got.A != "x" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	notJSON, err := b.Seal([]byte("{"), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.OpenJSON(notJSON, &got); err == nil {
		t.Fatal("opened a box that holds no JSON")
	}
	if err := b.OpenJSON("garbage", &got); err == nil {
		t.Fatal("opened garbage")
	}
	if _, err := b.SealJSON(func() {}, now.Add(time.Minute)); err == nil {
		t.Fatal("sealed a value JSON cannot encode")
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
