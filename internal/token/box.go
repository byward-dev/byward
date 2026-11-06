package token

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// Box seals arbitrary bytes for one purpose with the key ring: the broker's login-in-progress
// cookie (ADR-0007 §3) and the IdP tokens kept in the store (ADR-0006 §1). The purpose and the
// expiry are associated data, so a box sealed for one purpose never opens for another, and an
// expired box does not open at all.
//
// ADR-0006 §8 asks for separate keys per purpose; v0.1 uses one key ring with the purpose bound
// as associated data, which separates the domains cryptographically. Separate key directories are
// a follow-up.
type Box struct {
	ring    *KeyRing
	purpose string
	now     func() time.Time
}

const boxLabel = "byward box\x00"

var errBoxExpired = errors.New("token: box expired")

// NewBox binds ring to purpose (a short constant such as "login" or "idp-tokens").
func NewBox(ring *KeyRing, purpose string, now func() time.Time) (*Box, error) {
	if ring == nil || purpose == "" || len(purpose) > 64 {
		return nil, errors.New("token: a box needs a key ring and a purpose of at most 64 bytes")
	}
	if now == nil {
		now = time.Now
	}
	return &Box{ring: ring, purpose: purpose, now: now}, nil
}

// Seal returns plain sealed until expiresAt, base64url-encoded.
func (b *Box) Seal(plain []byte, expiresAt time.Time) (string, error) {
	exp := expiresAt.Unix()
	if exp <= b.now().Unix() {
		return "", errBoxExpired
	}
	k := b.ring.signing
	header := append([]byte{formatVersion, byte(len(k.id))}, k.id...) //nolint:gosec // G115: key IDs are at most 64 bytes
	header = binary.BigEndian.AppendUint64(header, uint64(exp))       //nolint:gosec // G115: checked positive above
	sealed := k.aead.Seal(header, nil, plain, b.ad(k.id, exp))        //nolint:gosec // G407: random nonce from the AEAD
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open returns the plain bytes of a box that is unexpired, sealed for this purpose, with a key in
// the ring. Every failure looks the same.
func (b *Box) Open(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) < 2 || raw[0] != formatVersion {
		return nil, errOpen
	}
	n := int(raw[1])
	if n == 0 || len(raw) < 2+n+8 {
		return nil, errOpen
	}
	kid := string(raw[2 : 2+n])
	exp := int64(binary.BigEndian.Uint64(raw[2+n : 2+n+8])) //nolint:gosec // G115: sealed as associated data
	k, err := b.ring.lookup(kid)
	if err != nil {
		return nil, errOpen
	}
	plain, err := k.aead.Open(nil, nil, raw[2+n+8:], b.ad(kid, exp))
	if err != nil {
		return nil, errOpen
	}
	if exp <= b.now().Unix() {
		return nil, errBoxExpired
	}
	return plain, nil
}

func (b *Box) ad(kid string, exp int64) []byte {
	a := []byte(boxLabel)
	a = append(a, formatVersion)
	a = binary.BigEndian.AppendUint16(a, uint16(len(kid))) //nolint:gosec // G115: at most 64
	a = append(a, kid...)
	a = binary.BigEndian.AppendUint64(a, uint64(exp))            //nolint:gosec // G115: positive
	a = binary.BigEndian.AppendUint16(a, uint16(len(b.purpose))) //nolint:gosec // G115: at most 64
	return append(a, b.purpose...)
}
